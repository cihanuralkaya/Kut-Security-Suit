// Package authz, KUT'un merkezi Action Authorization Gateway'idir: yüksek-etkili
// her operasyon (Rules / SOAR / AI / Human fark etmez) hedefe uygulanmadan ÖNCE
// buradan geçer. Amaç, güvenlik kararlarını tek deterministik sınırda toplamak —
// böylece gelecekte ML/LLM/otomasyon eklendiğinde bunlar yalnız birer "talepçi"
// olur ve bu sınırı ASLA atlayamaz ("güvenlik sistemi AI'ı da yönetir").
//
// Bu paket saf Go'dur ve dışarıya bağımlılık taşımaz; kararlar açıklanabilir
// (Decision.Reason) ve fail-closed'dır. Şu an iki deterministik kontrol sağlar:
//
//   - Blast-radius: tek bir talepte etkilenen cihaz sayısını sınırlar. İnsan
//     talepçi yumuşak-tavanı açık onayla (Confirmed) aşabilir; otomasyon/AI
//     talepçileri sert otonom tavanı HİÇBİR şekilde aşamaz (insan onayı gerekir).
//   - Rate-limit: talepçi başına dakikadaki yüksek-etkili operasyon sayısını
//     sınırlar (ele geçirilmiş bir oturumun hızlı kitlesel eylemini yavaşlatır).
//
// İleride Scope/ROE, RBAC ve dual-control kontrolleri de bu Gateway altında
// birleştirilebilir; şimdilik onlar admin.Service içinde yaşamaya devam eder.
package authz

import (
	"fmt"
	"sync"
	"time"

	"kut.corp/suite/server/internal/scope"
)

// Requester, bir operasyonu talep eden aktör sınıfıdır. İnsan dışı talepçiler
// (kural motoru, SOAR, AI) sert otonom sınırlara tabidir.
type Requester string

const (
	Human Requester = "human" // konsoldaki bir yönetici (varsayılan)
	Rule  Requester = "rule"  // deterministik kural/korelasyon motoru
	SOAR  Requester = "soar"  // otomatik yanıt playbook'u
	AI    Requester = "ai"    // ML/LLM türevi öneri
)

// autonomous, talepçinin insan onayı olmadan yüksek-etkili eylem yürütebilen bir
// otomasyon olup olmadığını döner (Human hariç hepsi).
func (r Requester) autonomous() bool { return r != Human }

// Request, yetkilendirilecek tek bir operasyonu tanımlar.
type Request struct {
	Requester   Requester    // talebi yapan aktör (boş = Human)
	Principal   string       // talepçi kimliği (admin id / playbook id) — rate-limit anahtarı
	Action      scope.Action // niyet edilen aksiyon (etki sınıfı bundan türetilir)
	TargetCount int          // etkilenecek cihaz sayısı (blast-radius)
	Confirmed   bool         // insan talepçi yumuşak-tavanı açıkça onayladı mı
}

// Code, kararın MAKİNE-OKUNUR gerekçesidir (çeviri/köprü için). Reason serbest
// metindir; Code deterministik eşlemeye izin verir (boş = ek gerekçe yok/allow).
type Code string

const (
	CodeBlastRadius Code = "BLAST_RADIUS"
	CodeRateLimit   Code = "RATE_LIMIT"
)

// Decision, Gateway'in kararıdır. Allow=false iken NeedApproval, kararın "kalıcı
// red" mi yoksa "insan onayı ile aşılabilir" mi olduğunu ayırt eder. Code, gerekçenin
// makine-okunur sınıfıdır (Reason'ı parse etmeden çeviri yapmak için).
type Decision struct {
	Allow        bool
	NeedApproval bool // true: kalıcı red değil, insan onayı/daraltma ile geçilebilir
	Reason       string
	Code         Code // makine-okunur gerekçe (deny/need-approval'da dolu; allow'da boş)
}

func allow() Decision { return Decision{Allow: true} }

// Policy, Gateway'in ayarlanabilir eşikleridir. Sıfır-değer güvenli değildir;
// üretim için NewGateway varsayılanlarını kullanın.
type Policy struct {
	// SoftBlastRadius, insan talepçinin açık onay (Confirmed) OLMADAN
	// etkileyebileceği azami cihaz sayısıdır. Aşımda NeedApproval.
	SoftBlastRadius int
	// HardAutonomousRadius, insan-dışı (AI/SOAR/Rule) talepçinin insan onayı
	// olmadan etkileyebileceği azami cihaz sayısıdır. Aşımda kalıcı RED.
	HardAutonomousRadius int
	// HighImpactPerMin, talepçi başına dakikadaki azami yüksek-etkili
	// operasyon sayısıdır (0 = sınırsız).
	HighImpactPerMin int
}

// DefaultPolicy, güvenli üretim varsayılanlarını döner. SoftBlastRadius mevcut
// toplu-eylem onay tavanıyla (500) hizalıdır; HardAutonomousRadius operatörün
// belirttiği "otonom izolasyon = 3" ilkesini uygular.
func DefaultPolicy() Policy {
	return Policy{
		SoftBlastRadius:      500,
		HardAutonomousRadius: 3,
		HighImpactPerMin:     30,
	}
}

// Gateway, merkezi yetkilendirme motorudur. Eşzamanlı kullanım için güvenlidir.
type Gateway struct {
	policy Policy
	now    func() time.Time

	mu   sync.Mutex
	hits map[string][]time.Time // principal → yüksek-etkili op zaman damgaları (kayan pencere)
}

// NewGateway, verilen politikayla bir Gateway oluşturur. now nil ise time.Now.
func NewGateway(p Policy) *Gateway {
	return &Gateway{policy: p, now: time.Now, hits: map[string][]time.Time{}}
}

// Authorize, bir operasyonu politikadan geçirir ve açıklanabilir bir Decision
// döner. Yüksek-etkili operasyonlar için sıra: blast-radius → rate-limit.
func (g *Gateway) Authorize(req Request) Decision {
	if req.Requester == "" {
		req.Requester = Human
	}
	if req.TargetCount < 1 {
		req.TargetCount = 1
	}
	imp := scope.ImpactOf(req.Action)

	// Düşük-etkili operasyonlar (passive/active/remote) gateway'i doğrudan geçer.
	if imp < scope.HighImpact {
		return allow()
	}

	if d := g.checkBlastRadius(req); !d.Allow {
		return d
	}
	if d := g.checkRate(req); !d.Allow {
		return d
	}
	return allow()
}

// checkBlastRadius, tek talepte etkilenen cihaz sayısını sınırlar.
func (g *Gateway) checkBlastRadius(req Request) Decision {
	if req.Requester.autonomous() {
		if req.TargetCount > g.policy.HardAutonomousRadius {
			return Decision{Code: CodeBlastRadius, Reason: fmt.Sprintf(
				"blast-radius: otonom talepçi (%s) %d cihaz isteyemez — otonom tavan %d; insan onayı gerekli",
				req.Requester, req.TargetCount, g.policy.HardAutonomousRadius)}
		}
		return allow()
	}
	// İnsan talepçi: yumuşak-tavanı yalnız açık onayla aşabilir.
	if req.TargetCount > g.policy.SoftBlastRadius && !req.Confirmed {
		return Decision{NeedApproval: true, Code: CodeBlastRadius, Reason: fmt.Sprintf(
			"blast-radius: %d cihaz yumuşak-tavanı (%d) aşıyor — açık onay gerekli",
			req.TargetCount, g.policy.SoftBlastRadius)}
	}
	return allow()
}

// rateKeyCap, hits map'i için fırsatçı-süpürme tetikleme tavanıdır (bellek sınırlama).
// Aşılınca süresi dolmuş anahtarlar temizlenir. Test edilebilirlik için var (sabit değil).
var rateKeyCap = 8192

// checkRate, talepçi başına yüksek-etkili operasyon hızını sınırlar (kayan 60s
// penceresi). Sınır aşılırsa kalıcı RED değil — geçici; talepçi beklemeli.
func (g *Gateway) checkRate(req Request) Decision {
	if g.policy.HighImpactPerMin <= 0 {
		return allow()
	}
	key := string(req.Requester) + ":" + req.Principal
	now := g.now()
	cutoff := now.Add(-time.Minute)

	g.mu.Lock()
	defer g.mu.Unlock()
	// Fırsatçı süpürme: hits map'i bir tavanı aşarsa, TÜM girdileri süresi dolmuş
	// anahtarları sil. Aksi halde seyrek erişilen principal'lar (AI/SOAR/kural/playbook
	// kimlikleri) map'te sonsuza dek kalır — süreç-ömrü boyunca bellek sızıntısı. O(n)
	// yalnız tavan aşımında (nadir); amortize maliyet düşük.
	if len(g.hits) > rateKeyCap {
		for k, ts := range g.hits {
			stale := true
			for _, t := range ts {
				if t.After(cutoff) {
					stale = false
					break
				}
			}
			if stale {
				delete(g.hits, k)
			}
		}
	}
	// Pencere dışını buda.
	kept := g.hits[key][:0]
	for _, t := range g.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= g.policy.HighImpactPerMin {
		g.hits[key] = kept
		return Decision{Code: CodeRateLimit, Reason: fmt.Sprintf(
			"rate-limit: %s dakikada %d yüksek-etkili op sınırını aştı — bekleyin",
			key, g.policy.HighImpactPerMin)}
	}
	g.hits[key] = append(kept, now)
	return allow()
}
