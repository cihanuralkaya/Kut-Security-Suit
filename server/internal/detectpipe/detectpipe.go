// Package detectpipe holds the server-side detection suppression gates that
// decide whether a raw detection (from the live detect.Engine) becomes an alert:
// multi-stage detection bits (flowbits/xbits), the repeat-threshold gate, and
// correlation suppression.
//
// These gates are STATEFUL (windows, counters, bit stores) and there must be
// exactly ONE set of them per server, shared by every ingest path — the gRPC
// agent stream, the HTTP log-ingest path, and the telemetry plane — so that all
// paths see the same windows and counters and no path can raise an alert that
// another path would have suppressed. Previously this logic lived inline in the
// gRPC AgentHandler; extracting it here lets the telemetry plane reuse the SAME
// gate instances instead of carrying a second, ungated detection stack.
package detectpipe

import (
	"context"
	"strings"
	"time"

	"kut.corp/suite/server/internal/correlate"
	"kut.corp/suite/server/internal/detbits"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/threshold"
)

// ScopeKey maps a rule's Track ("device"|"tenant"|"global", default device) plus
// the device and tenant to the scope string that keys the threshold counters and
// detection bits. It is the single source of truth for gate scoping; callers that
// keep a local name (e.g. the gRPC handler) alias this function.
func ScopeKey(track, deviceID, tenantID string) string {
	switch strings.ToLower(strings.TrimSpace(track)) {
	case "tenant":
		return "tenant:" + tenantID
	case "global":
		return "global"
	default: // "device" veya "" → cihaz başına (uç-nokta için varsayılan)
		return "device:" + deviceID
	}
}

// Gate applies the bits, repeat-threshold and correlation suppression gates over
// one set of stateful components. A nil component disables its stage (the bits
// and threshold gates are always configured in practice; the correlator is
// optional). Build it with the server's single component instances so every
// ingest path shares the same state.
type Gate struct {
	threshold  *threshold.Gate
	detbits    *detbits.Store
	correlator *correlate.Correlator
}

// NewGate wraps the server's single stateful gate components. The returned Gate
// holds the same pointers it is given, so state (windows, counters, bits,
// correlation) is shared with every other caller of those instances.
func NewGate(th *threshold.Gate, bits *detbits.Store, corr *correlate.Correlator) *Gate {
	return &Gate{threshold: th, detbits: bits, correlator: corr}
}

// Admit runs the bits precondition/state, repeat-threshold and correlation
// suppression gates for one detection against one event and reports whether the
// detection should raise an alert. It returns false (with the matching
// gated/suppressed metric already incremented) when the detection must be
// suppressed, true when the caller should raise the alert. Side effects — writing
// a rule's Set bits and recording the detection in the correlator — are identical
// to the canonical agent path, so moving a caller onto this gate does not change
// detection behaviour.
func (g *Gate) Admit(ctx context.Context, deviceID string, e model.Event, d detect.Detection) bool {
	// Çok-aşamalı tespit bitleri (opt-in, flowbits/xbits): önce ön-koşul (Require)
	// — host'ta gerekli bitler kurulu değilse bu tespit alarma dönüşmez (aşama-2,
	// aşama-1 görülmeden susar). Ön-koşul sağlanınca kuralın Set bitleri host'a
	// yazılır. Bitsiz kurallar bu daldan etkilenmez.
	if d.Bits != nil && g.detbits != nil {
		bscope := ScopeKey(d.Bits.Track, deviceID, e.TenantID)
		if len(d.Bits.Require) > 0 && !g.detbits.AllSet(bscope, d.Bits.Require) {
			metrics.IncBitsGated()
			return false
		}
		if len(d.Bits.RequireNot) > 0 && !g.detbits.NoneSet(bscope, d.Bits.RequireNot) {
			metrics.IncBitsGated()
			return false
		}
		if len(d.Bits.Set) > 0 {
			ttl := time.Duration(d.Bits.TTLSeconds) * time.Second
			for _, b := range d.Bits.Set {
				g.detbits.Set(bscope, b, ttl)
			}
		}
	}
	// Tekrar-eşiği (opt-in): kural bir eşik tanımlıyorsa, tespit pencerede Count'a
	// ULAŞMADAN alarma dönüşmez. Tek başarısız deneme susar; brute-force yakalanır.
	// Eşiksiz kurallar bu daldan hiç etkilenmez.
	if d.Threshold != nil && d.Threshold.Count > 1 && g.threshold != nil {
		scope := ScopeKey(d.Threshold.Track, deviceID, e.TenantID)
		win := time.Duration(d.Threshold.Seconds) * time.Second
		if !g.threshold.Allow(d.RuleID, scope, d.Threshold.Count, win) {
			metrics.IncThresholdGated()
			return false
		}
	}
	// Korelasyon: aynı cihaz+kural penceresindeki tekrarları tek incident'e katla
	// ve YİNELENEN alarmı bastır (alarm-fırtınası).
	if g.correlator != nil {
		if _, suppress := g.correlator.Observe(ctx, deviceID, d.RuleID, d.Technique.ID, d.Severity, e.Message); suppress {
			metrics.IncAlertSuppressed()
			return false
		}
	}
	return true
}
