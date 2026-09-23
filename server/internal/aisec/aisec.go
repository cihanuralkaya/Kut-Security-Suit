// Package aisec, Milestone AG'nin (Agentic Threat Defense Plane; docs/CONTRACTS.md §22,
// namespace KUT-AI-SEC-*) deterministik VERİ-ZEMİNİ ve INV-AG invariant'larıdır. Amaç:
// saldırganın AI-agent'larını ve karma (insan/yazılım/AI) principal davranışını
// modelleyip Agent Causality Graph verisini üretmek (ör. `untrusted web → agent reads
// secret → external HTTP` = indirect prompt-injection → credential access → exfiltration).
//
// Bu paket §1-13 execution/authorization FREEZE'inden AYRIDIR ve o sınıra DOKUNMAZ
// (INV-AG-010/011): execution/authorization paketlerini (seccontract/secgateway/privman/
// admin) import ETMEZ. Enforcement deterministiktir; AI yalnız korelasyon/açıklama
// katmanındadır (§0 zinciri: AI → ActionRequest → Gateway → Grant → GuardedExecutor).
//
// AG-01 kapsamı: Agent Identity + Trust/Taint propagation + Delegation intersection
// (INV-AG-001/003/007). Sonraki dilimler: taint→exfiltration guard (INV-AG-004/005),
// memory provenance (INV-AG-006), tool allowlist deny-by-default (INV-AG-009).
package aisec

import "time"

// TrustLevel, bir principal/içerik/context'in güven düzeyidir (KUT-AI-SEC-006). SIRALI:
// Tainted < Untrusted < Trusted. Propagation MONOTON AŞAĞIDIR — birleşimde daima en
// düşük (en kirli) düzey kazanır; untrusted/tainted içerik principal'ı YÜKSELTEMEZ
// (INV-AG-001).
type TrustLevel int

const (
	Tainted   TrustLevel = iota // dış + etki zincirine girmiş (en düşük); şüpheli akış
	Untrusted                   // dış/kanıtlanmamış kaynak
	Trusted                     // kriptografik kimlikli, iç (en yüksek)
)

// String, güven düzeyinin okunur adıdır (audit/telemetri).
func (t TrustLevel) String() string {
	switch t {
	case Trusted:
		return "TRUSTED"
	case Untrusted:
		return "UNTRUSTED"
	default:
		return "TAINTED"
	}
}

// PropagateTrust, iki güven düzeyini birleştirir: sonuç daima en DÜŞÜK (en kirli) —
// monoton aşağı (INV-AG-001). Bir agent, untrusted/tainted bir context'i okuyunca kendi
// etkin güven düzeyi o context'in düzeyine (veya altına) DÜŞER, asla yükselmez.
func PropagateTrust(a, b TrustLevel) TrustLevel {
	if a < b {
		return a
	}
	return b
}

// ChainTrust, bir etki zinciri boyunca etkin güven düzeyini hesaplar (en kirli kazanır).
// Boş zincir = Trusted (nötr eleman); herhangi bir tainted girdi sonucu Tainted yapar.
func ChainTrust(levels ...TrustLevel) TrustLevel {
	out := Trusted
	for _, l := range levels {
		out = PropagateTrust(out, l)
	}
	return out
}

// Cap, bir agent principal'ının sahip olabileceği yetenektir (execution §11'den AYRI;
// bu düzlem agent-davranışını modeller). Ör. "credential.read", "external.write".
type Cap string

// CapSet, yetenek kümesidir.
type CapSet map[Cap]bool

// AgentPrincipal, bir AI-agent örneğinin KRİPTOGRAFİK kimliğidir (KUT-AI-SEC-001).
// Kimlik model ÇIKTISINDAN ÇIKARSANMAZ (INV-AG-007) — AgentID/InstanceID doğrulanmış
// kimlikten gelir. DelegatedBy delegation zincirini (KUT-AI-SEC-002) kurar.
type AgentPrincipal struct {
	AgentID        string
	InstanceID     string
	ModelID        string
	OwnerPrincipal string // sahibi (insan/servis) — nihai sorumluluk
	DelegatedBy    string // bu agent'ı delege eden principal (boş = kök)
	TenantID       string
	Capabilities   CapSet
	TrustLevel     TrustLevel
	ExpiresAt      time.Time
}

// Expired, agent kimliğinin süresi dolmuşsa true döner (fail-closed kullanım için).
func (a AgentPrincipal) Expired(now time.Time) bool {
	return !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt)
}

// EffectiveCapabilities, delegation zinciri + tenant politikası boyunca ETKİN yeteneği
// hesaplar: KESİŞİM (INV-AG-003). Delegation ASLA yetenek ARTIRAMAZ —
// effective = intersection(human, agentA, agentB, tool, tenant policy). Bir agent,
// kendisini delege edenin sahip OLMADIĞI bir yeteneği kazanamaz.
func EffectiveCapabilities(sets ...CapSet) CapSet {
	out := CapSet{}
	if len(sets) == 0 {
		return out
	}
	for c := range sets[0] {
		inAll := true
		for _, s := range sets[1:] {
			if !s[c] {
				inAll = false
				break
			}
		}
		if inAll {
			out[c] = true
		}
	}
	return out
}

// Allows, etkin yetenek kümesinin bir yeteneğe izin verip vermediğini döner.
func (c CapSet) Allows(cap Cap) bool { return c[cap] }
