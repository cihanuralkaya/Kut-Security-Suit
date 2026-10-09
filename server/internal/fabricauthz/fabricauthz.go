// Package fabricauthz, Sovereign Security Fabric düzlemlerinin (commandplane,
// aiprovider response ajanı, coordinator kaos motoru) KANONİK yetki kapılarını
// mevcut ve CANLI `scope.Engine`'e bağlayan üretim adaptörlerini sağlar.
//
// Remediation (C1/H1/L2), bu düzlemlerin yetkilendiricilerini ENJEKTE edilebilir
// bıraktı ve nil => fail-closed (hard-deny) yaptı. Bu paket o sözleşmenin eksik
// ÜRETİM kolu: kapıyı GEVŞETMEZ, zaten var olan tek otoriteye (scope/ROE motoru)
// bağlar — böylece dormant düzlemler "izin-veren" değil "etkinleştirilebilir" olur.
//
// ADDITIVE ve DAVRANIŞ-KORUYAN: yalnız salt-okunur scope KARARLARI okur; hiçbir raw
// Store mutasyonu çağırmaz (G-02 mimari-guard'ı tetiklenmez). Henüz hiçbir app/cmd
// bu paketi import etmez; bağımlılık oku tek yönlüdür (fabricauthz → düzlemler).
package fabricauthz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"kut.corp/suite/server/internal/aiprovider"
	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/coordinator"
	"kut.corp/suite/server/internal/scope"
)

// Derleme-zamanı arayüz doğrulamaları: adaptörler düzlem sözleşmelerini karşılamalı.
var (
	_ commandplane.Authorizer     = (*CommandAuthorizer)(nil)
	_ aiprovider.ActionAuthorizer = (*ResponseAuthorizer)(nil)
	_ coordinator.FaultAuthorizer = (*FaultAuthorizer)(nil)
)

// CommandAuthorizer, commandplane.Authorizer'ı scope.Engine üzerinden karşılar.
// Komut, sunucu kiracısı + hedef cihaz için scope/ROE kararına tabidir.
type CommandAuthorizer struct {
	eng    *scope.Engine
	tenant string
}

// NewCommandAuthorizer, verilen scope motoru ve kiracı için komut yetkilendiricisi
// üretir. Kiracı başına ayrı komut düzlemi, kiracı başına ayrı adaptörle bağlanır.
func NewCommandAuthorizer(eng *scope.Engine, tenant string) *CommandAuthorizer {
	return &CommandAuthorizer{eng: eng, tenant: tenant}
}

// Authorize, komut isteğini scope/ROE kararına çevirir. Motor yoksa fail-closed
// reddeder. Bilinmeyen aksiyon adı scope.ImpactOf'ta Destructive'e düşer (en katı).
func (c *CommandAuthorizer) Authorize(ctx context.Context, req commandplane.ActionRequest) (commandplane.AuthorizationDecision, error) {
	if c == nil || c.eng == nil {
		return commandplane.AuthorizationDecision{Allowed: false, Reason: "scope motoru yapılandırılmadı (fail-closed)"}, nil
	}
	act := scope.Action(strings.ToLower(strings.TrimSpace(req.Action)))
	tgt := scope.Target{Tenant: c.tenant, DeviceID: req.Object}
	d := c.eng.Authorize(tgt, act)
	return commandplane.AuthorizationDecision{Allowed: d.Allowed, Reason: d.Reason}, nil
}

// responseActionToScope, otonom yanıt aksiyon tiplerini scope aksiyonlarına eşler.
// Eşlenmemiş tip, ham küçük-harfli ada düşer → scope.ImpactOf = Destructive (fail-closed).
var responseActionToScope = map[aiprovider.ResponseActionType]scope.Action{
	aiprovider.ActionIsolateEndpoint: scope.ActionQuarantine,
	aiprovider.ActionQuarantineFile:  scope.ActionQuarantine,
	aiprovider.ActionKillProcess:     scope.ActionRestart,
	aiprovider.ActionRevokeSession:   scope.ActionLock,
	aiprovider.ActionBlockHash:       scope.ActionPolicyEnforce,
}

// ResponseAuthorizer, aiprovider.ActionAuthorizer'ı scope.Engine üzerinden karşılar.
// C1'in çift-kontrol/tenant kapısının ÜSTÜNE eklenen scope/ROE kapısıdır.
type ResponseAuthorizer struct {
	eng *scope.Engine
}

// NewResponseAuthorizer, verilen scope motoru için yanıt yetkilendiricisi üretir.
func NewResponseAuthorizer(eng *scope.Engine) *ResponseAuthorizer {
	return &ResponseAuthorizer{eng: eng}
}

// AuthorizeResponse, yanıt aksiyonunu aksiyonun kiracısı+hedefi için scope kararına
// çevirir. Motor yoksa veya onaylayan boşsa fail-closed reddeder.
func (r *ResponseAuthorizer) AuthorizeResponse(ctx context.Context, action aiprovider.ResponseAction, approver string) error {
	if r == nil || r.eng == nil {
		return errors.New("scope motoru yapılandırılmadı (fail-closed)")
	}
	if strings.TrimSpace(approver) == "" {
		return errors.New("onaylayan kimlik gerekli")
	}
	act, ok := responseActionToScope[action.Type]
	if !ok {
		act = scope.Action(strings.ToLower(string(action.Type)))
	}
	tgt := scope.Target{Tenant: action.TenantID, DeviceID: action.Target}
	if d := r.eng.Authorize(tgt, act); !d.Allowed {
		return fmt.Errorf("scope/ROE reddetti: %s", d.Reason)
	}
	return nil
}

// FaultAuthorizer, coordinator.FaultAuthorizer'ı yetkili-operatör allow-list'i ile
// karşılar. Kaos hedefi bir bölge/sağlayıcıdır (cihaz değil) → scope device-target
// modeline girmez; bu yüzden kanonik kapı açık operatör allow-list'idir. Boş liste
// => tüm enjeksiyonlar reddedilir (fail-closed).
type FaultAuthorizer struct {
	allowed map[string]bool
}

// NewFaultAuthorizer, verilen yetkili operatör kimlikleriyle bir kaos yetkilendiricisi
// üretir. Boş/yalnız-boşluk kimlikler yok sayılır; hiç geçerli operatör yoksa tüm
// enjeksiyonlar reddedilir.
func NewFaultAuthorizer(operators ...string) *FaultAuthorizer {
	m := make(map[string]bool, len(operators))
	for _, o := range operators {
		if o = strings.TrimSpace(o); o != "" {
			m[o] = true
		}
	}
	return &FaultAuthorizer{allowed: m}
}

// AuthorizeFault, aktörün kaos enjeksiyonuna yetkili olup olmadığını döner. Yetkili
// operatör tanımlı değilse veya aktör listede yoksa reddeder.
func (f *FaultAuthorizer) AuthorizeFault(ctx context.Context, actor string, fault coordinator.ChaosFaultType, target string) error {
	if f == nil || len(f.allowed) == 0 {
		return errors.New("kaos enjeksiyonu için yetkili operatör tanımlı değil (fail-closed)")
	}
	if !f.allowed[strings.TrimSpace(actor)] {
		return fmt.Errorf("aktör %q kaos enjeksiyonuna yetkili değil", actor)
	}
	return nil
}
