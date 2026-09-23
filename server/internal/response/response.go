// Package response, otomatik müdahale (auto-response) mantığıdır: kritik güvenlik
// olaylarında insan beklemeden cihazı karantinaya alır (SOAR benzeri, hafif).
// Yapılandırma ile açılır (varsayılan kapalı — karantina bozucu bir eylemdir).
//
// Milestone A / PR-03 (audit G-01): otomatik karantina artık raw executor'a ulaşmadan
// ÖNCE yetki-karar sınırından (secgateway) geçer. Fail-closed: ALLOW değilse karantina
// YOK. Bu, "AutoQuarantine → executor TAM BYPASS" bulgusunu kapatır — otonom talepçi
// artık tenant + blast-radius + rate-limit kontrolüne tabidir.
package response

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"kut.corp/suite/server/internal/authz"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/scope"
	"kut.corp/suite/server/internal/seccontract"
	"kut.corp/suite/server/internal/secgateway"
)

// systemActor, otomatik müdahalenin denetim izindeki fail (adminID yerine sistem).
const systemActor = "" // boş → denetim kaydı 'sistem' kaynaklı (created_by NULL)

// Store, otomatik karantina için gereken minimal depo yeteneğidir (backend bunu
// zaten karşılar).
type Store interface {
	EnqueueCommand(ctx context.Context, deviceID, cmdType, issuedBy string) error
	SetDeviceStatus(ctx context.Context, deviceID, status string) error
	WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error
}

// Authorizer, otomatik müdahalenin yetki-karar sınırıdır (secgateway.Gateway bunu
// karşılar). ActionRequest'i AuthorizationDecision'a çevirir; ALLOW değilse eylem yok.
type Authorizer interface {
	Authorize(req seccontract.ActionRequest) seccontract.AuthorizationDecision
}

// AutoQuarantiner, kritik olaylara karantina ile yanıt verir.
type AutoQuarantiner struct {
	store    Store
	authz    Authorizer // nil = geçiş (transitional); üretimde daima kurulur (NewGuarded)
	tenantID string     // yapılandırılmış kiracı (CONTRACTS §10; fail-closed gateway için)
}

// New, verilen yetki-karar sınırıyla bir AutoQuarantiner kurar (dependency injection —
// testler stub Authorizer verebilir). authorizer nil ise gate atlanır (yalnız geçiş).
func New(store Store, authorizer Authorizer, tenantID string) *AutoQuarantiner {
	return &AutoQuarantiner{store: store, authz: authorizer, tenantID: tenantID}
}

// NewGuarded, üretim için varsayılan secgateway'i (blast-radius + rate-limit) kurup
// bağlar. Otonom talepçi (autoresponder) sert tavana tabidir; tek-cihaz karantina
// (hedef=1) normalde geçer, kitlesel/aşırı-hızlı otomatik karantina engellenir.
func NewGuarded(store Store, tenantID string) *AutoQuarantiner {
	gw := secgateway.New(
		authz.NewGateway(authz.DefaultPolicy()),
		seccontract.PolicyFunc(func(seccontract.ActionRequest) string { return "autoresp-policy-v1" }),
		nil, // time.Now
		randGrantID,
		5*time.Minute,
	)
	return New(store, gw, tenantID)
}

// AutoQuarantine, cihaza karantina komutu kuyruğa alır, durumu QUARANTINED yapar
// ve denetim izine (sistem kaynaklı) yazar. ÖNCE yetki-karar sınırından geçer;
// ALLOW değilse hiçbir yan-etki üretmeden hata döner (fail-closed, G-01).
func (a *AutoQuarantiner) AutoQuarantine(ctx context.Context, deviceID, reason string) error {
	// G-01: raw executor'a ulaşmadan ÖNCE gateway (tenant + blast-radius + rate-limit).
	if a.authz != nil {
		req := seccontract.ActionRequest{
			RequestID: "autoresp-" + deviceID,
			TenantID:  a.tenantID,
			Principal: seccontract.Principal{Type: seccontract.PrincipalAutoResponder, ID: "auto-quarantine"},
			Action:    scope.ActionQuarantine,
			Targets:   []string{deviceID},
		}
		if d := a.authz.Authorize(req); d.Result != seccontract.ResultAllow {
			return fmt.Errorf("response: otomatik karantina yetkilendirilmedi (%s): %v", d.Result, d.ReasonCodes)
		}
	}
	if err := a.store.EnqueueCommand(ctx, deviceID, "QUARANTINE", systemActor); err != nil {
		return fmt.Errorf("response: karantina komutu kuyruğa alınamadı: %w", err)
	}
	_ = a.store.SetDeviceStatus(ctx, deviceID, "QUARANTINE_PENDING") // DESIRED; effective ajan onayıyla (F-D)
	_ = a.store.WriteAudit(ctx, systemActor, "AUTO_QUARANTINE", "device", deviceID)
	return nil
}

// randGrantID, grant kimliği/nonce için kısa rastgele bir kimlik üretir (crypto/rand).
func randGrantID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "g_fallback"
	}
	return "g_" + hex.EncodeToString(b[:])
}

// ShouldTrigger, bir olay grubunun otomatik karantinayı hak edip etmediğini söyler.
// Tetikleyici: en az bir KRİTİK önem düzeyli olay (kurcalama, sahte güncelleme/
// script reddi, karantina-kaçışı gibi). Tetikleyen ilk olayın mesajı gerekçe olur.
func ShouldTrigger(events []model.Event) (reason string, ok bool) {
	for _, e := range events {
		if e.Severity == "CRITICAL" {
			return e.Message, true
		}
	}
	return "", false
}
