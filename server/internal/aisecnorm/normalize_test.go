package aisecnorm

import (
	"encoding/json"
	"testing"
	"time"

	"kut.corp/suite/server/internal/aisec"
)

func mkFinding(agent string, trust aisec.TrustLevel) aisec.ExfilFinding {
	return aisec.ExfilFinding{AgentID: agent, Credential: "cred:aws", Sink: "external:pastebin", Trust: trust}
}

func TestFindingToEventMapping(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	e := FindingToEvent(mkFinding("agent-1", aisec.Tainted), "t1", 7, at)

	if e.Severity != "CRITICAL" {
		t.Errorf("Tainted → CRITICAL bekleniyordu: %s", e.Severity)
	}
	if e.Confidence != 0.9 {
		t.Errorf("Tainted güven 0.9 bekleniyordu: %v", e.Confidence)
	}
	if e.Source != SourceAgentSec || e.EventType != EventTypeExfil || e.Category != CategoryAISec {
		t.Errorf("kanonik sınıflandırma yanlış: src=%s type=%s cat=%s", e.Source, e.EventType, e.Category)
	}
	if e.TenantID != "t1" || e.DeviceID != "agent-1" || e.Sequence != 7 {
		t.Errorf("atıf/sıra yanlış: tenant=%s device=%s seq=%d", e.TenantID, e.DeviceID, e.Sequence)
	}
	if !e.OccurredAt.Equal(at) {
		t.Errorf("OccurredAt korunmalı: %v", e.OccurredAt)
	}
	if e.EventID == "" {
		t.Error("EnsureID içerik-adresli kimlik atamalı (boş)")
	}

	// Details, yapılandırılmış ve tam olmalı.
	var d map[string]string
	if err := json.Unmarshal([]byte(e.Details), &d); err != nil {
		t.Fatalf("Details geçerli JSON olmalı: %v", err)
	}
	if d["agent_id"] != "agent-1" || d["credential"] != "cred:aws" || d["sink"] != "external:pastebin" || d["trust"] != "TAINTED" {
		t.Errorf("Details alanları eksik/yanlış: %v", d)
	}
}

func TestSeverityForUntrusted(t *testing.T) {
	e := FindingToEvent(mkFinding("a", aisec.Untrusted), "t1", 1, time.Unix(1, 0))
	if e.Severity != "HIGH" || e.Confidence != 0.75 {
		t.Errorf("Untrusted → HIGH/0.75 bekleniyordu: sev=%s conf=%v", e.Severity, e.Confidence)
	}
}

// TestEventIDStableForDedup, AYNI bulgunun (aynı seq/tenant/zaman) her çevrimde AYNI kimliği
// verdiğini doğrular — kanonik dedup (§6) / replay idempotensi (§19) bunun üzerine kuruludur.
// FARKLI agent farklı kimlik vermeli (yanlış birleştirme olmamalı).
func TestEventIDStableForDedup(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	a := FindingToEvent(mkFinding("agent-1", aisec.Tainted), "t1", 5, at)
	b := FindingToEvent(mkFinding("agent-1", aisec.Tainted), "t1", 5, at)
	if a.EventID != b.EventID {
		t.Errorf("aynı bulgu aynı EventID vermeli (dedup): %s != %s", a.EventID, b.EventID)
	}
	c := FindingToEvent(mkFinding("agent-2", aisec.Tainted), "t1", 5, at)
	if a.EventID == c.EventID {
		t.Error("farklı agent farklı EventID vermeli (yanlış birleştirme)")
	}
}

func TestFindingsToEventsSequencing(t *testing.T) {
	if got := FindingsToEvents(nil, "t1", 0, time.Now()); got != nil {
		t.Errorf("boş girdi nil dönmeli: %v", got)
	}
	fs := []aisec.ExfilFinding{
		mkFinding("a1", aisec.Tainted),
		mkFinding("a2", aisec.Untrusted),
	}
	evs := FindingsToEvents(fs, "t1", 10, time.Unix(1, 0))
	if len(evs) != 2 {
		t.Fatalf("2 olay bekleniyordu: %d", len(evs))
	}
	if evs[0].Sequence != 10 || evs[1].Sequence != 11 {
		t.Errorf("sequence baseSeq'ten artmalı: %d,%d", evs[0].Sequence, evs[1].Sequence)
	}
	if evs[0].EventID == evs[1].EventID {
		t.Error("farklı bulgular farklı kimlik vermeli")
	}
}
