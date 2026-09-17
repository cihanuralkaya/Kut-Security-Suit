// Package seccontract, KUT güvenlik sözleşmelerinin (docs/CONTRACTS.md v3.2.1 —
// PR-00B FREEZE baseline) mekanik karşılığıdır: tipler, enum'lar, durum makineleri
// ve GuardedExecutor sınırı. Bu paket ADDITIVE'dir — mevcut execution yollarını
// migrate ETMEZ, davranış DEĞİŞTİRMEZ (bkz. CONTRACTS.md §20). Sonraki PR'lar
// (Milestone A) canlı authz/admin yollarını bu sözleşmelere taşır.
//
// Değişmez kural (CONTRACTS.md): kod sözleşmeye uymuyorsa varsayılan karar
// implementasyonu düzeltmektir, sözleşmeyi değil.
package seccontract

import (
	"errors"
	"strings"
)

// trimLowerSpace, kanonik kiracı/kimlik karşılaştırması için boşluk kırpar + küçültür.
func trimLowerSpace(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// PrincipalType, bir eylemi talep eden aktör sınıfıdır (CONTRACTS §1/§11).
type PrincipalType string

const (
	PrincipalHuman         PrincipalType = "human"
	PrincipalAI            PrincipalType = "ai"
	PrincipalSOAR          PrincipalType = "soar"
	PrincipalRule          PrincipalType = "rule"
	PrincipalAutoResponder PrincipalType = "autoresponder"
	PrincipalScheduled     PrincipalType = "scheduled"
)

// Principal, kimlik-doğrulamadan gelen talepçi kimliğidir. İstemciden HAM kabul
// edilmez (CONTRACTS §1).
type Principal struct {
	Type PrincipalType
	ID   string
}

// Autonomous, principal'ın insan-dışı (otomasyon/AI) olup olmadığını döner.
func (p Principal) Autonomous() bool { return p.Type != PrincipalHuman }

// Sözleşme hataları — reason-code'larla (CONTRACTS §2) eşlenir.
var (
	ErrTenantMissing       = errors.New("seccontract: tenant kimliği eksik")            // INV-044
	ErrGrantMissing        = errors.New("seccontract: grant yok")                       // INV-001
	ErrGrantExpired        = errors.New("seccontract: grant süresi dolmuş")             // INV-002
	ErrGrantReplayed       = errors.New("seccontract: grant zaten tüketildi (replay)")  // INV-003
	ErrGrantMismatch       = errors.New("seccontract: grant isteğe/politikaya uymuyor") // INV-004..007
	ErrApprovalInvalid     = errors.New("seccontract: onay geçersiz/uyumsuz")           // INV-009/010/040
	ErrForbiddenCapability = errors.New("seccontract: yasak capability")                // INV-AI-001/035
)

// NormTenant, kiracı kimliğini normalize eder. Boş kiracı **DENY** anlamına gelir
// (INV-044): güvenlik nesnesinde implicit "default"a düşme YASAK; boş → hata.
// (Tek-kiracılı uyum, açıkça yapılandırılmış bir tenant ile sağlanır — CONTRACTS §10.)
func NormTenant(tenantID string) (string, error) {
	t := trimLowerSpace(tenantID)
	if t == "" {
		return "", ErrTenantMissing
	}
	return t, nil
}
