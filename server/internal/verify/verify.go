// Package verify — Remediation Verification (KUT-VERIFY). DETECTION → RESPONSE →
// VERIFICATION omurgasının son halkası: bir bulgu/aksiyon sonrasında, kaynak tespit
// sinyalinin GERÇEKTEN kaybolup kaybolmadığını taze telemetriye karşı yeniden ölçer.
// Bir bulgu ancak sinyal doğrulanabilir biçimde yoksa VERIFIED olur; aksi halde
// REGRESSED/INCONCLUSIVE. FAIL-CLOSED: değerlendirilemeyen bir check ASLA VERIFIED
// vermez (bu yüzden çekirdek-içi ve deterministiktir; fail-open bir dış servise konmaz).
//
// Bu dosya (Dilim 1) yalnız tipleri ve kiracı-kapsamlı depoyu içerir; kural yeniden-koşumu
// (Verifier) ve risk-hesabı sonraki dilimlerde eklenir. Saf-stdlib (zero-dep Lite uyumlu).
package verify

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"kut.corp/suite/server/internal/risk"
)

// Outcome, bir doğrulama check'inin sonucudur.
type Outcome string

const (
	OutcomePending      Outcome = "PENDING"      // henüz değerlendirilmedi (pencere dolmadı)
	OutcomeVerified     Outcome = "VERIFIED"     // sinyal doğrulanabilir biçimde kayboldu
	OutcomeRegressed    Outcome = "REGRESSED"    // sinyal hâlâ tetikliyor (düzelme YOK)
	OutcomeInconclusive Outcome = "INCONCLUSIVE" // pencerede telemetri yok → karar verilemez (fail-closed)
)

// Kind, bir check'in ne tür bir sinyali yeniden ölçtüğüdür.
const (
	KindDetection    = "detection"     // bir detect.Rule'un artık tetiklememesi
	KindDeviceStatus = "device_status" // bir cihazın beklenen duruma (ör. ACTIVE) dönmesi
	// (rezerve: "vuln", "compliance" — sonraki dilimler)
)

// Hatalar.
var (
	// ErrCheckNotFound, check bulunamazsa VEYA kiracı eşleşmezse döner (varlık sızmaz).
	ErrCheckNotFound = errors.New("verify: check bulunamadı")
	// ErrTenantRequired, kiracı kimliği boş verildiğinde döner (kiracı-kapsamlı işlem).
	ErrTenantRequired = errors.New("verify: kiracı kimliği gerekli")
	// ErrIDRequired, check kimliği boş verildiğinde döner.
	ErrIDRequired = errors.New("verify: check kimliği gerekli")
)

// Check, açılmış bir doğrulama işlemidir. TenantID SUNUCU-TARAFI atanır (çağıranın
// kiracısı); istemciden gelmez. Baseline, açılışta bulgunun risk skoru; ResidualRisk,
// değerlendirme sonrası kalan risk.
type Check struct {
	ID         string       `json:"id"`
	TenantID   string       `json:"tenant_id"`
	FindingRef string       `json:"finding_ref"` // bağlı bulgu/olay/incident kimliği
	DeviceID   string       `json:"device_id"`
	RuleID     string       `json:"rule_id"` // yeniden koşulacak tespit kuralı (Kind=detection)
	Kind       string       `json:"kind"`
	Factors    risk.Factors `json:"factors"` // bulgunun açılıştaki risk girdileri; Baseline bundan türer
	Baseline   int          `json:"baseline"`
	Residual   int          `json:"residual_risk"`
	Outcome    Outcome      `json:"outcome"`
	OpenedAt   time.Time    `json:"opened_at"`
	WindowEnd  time.Time    `json:"window_end"`  // bu andan sonra değerlendirilebilir
	VerifiedAt time.Time    `json:"verified_at"` // çözümleme anı (Resolve)
}

// RiskReduced, gerçekleşen (ölçülen) risk azalmasıdır: Baseline − Residual, 0'da taban.
// REGRESSED'de Residual≈Baseline → ~0; VERIFIED'de Residual düşük → pozitif.
func (c Check) RiskReduced() int {
	d := c.Baseline - c.Residual
	if d < 0 {
		return 0
	}
	return d
}

// Store, doğrulama check'lerinin kalıcı deposudur. Kiracı-kapsamlıdır: Get/List yalnız
// verilen kiracının check'lerini döner (çapraz-kiracı sızıntı yok). MemStore (bellek-içi)
// ve ileride DB destekli bir depo bunu karşılar.
type Store interface {
	// Open, yeni bir check açar (Outcome boşsa PENDING'e ayarlanır). id/tenant boşsa hata.
	Open(c Check) (Check, error)
	// Get, verilen kiracının check'ini döner. Kiracı eşleşmez/yoksa ErrCheckNotFound.
	Get(tenantID, id string) (Check, error)
	// List, verilen kiracının check'lerini OpenedAt'e göre (eskiden yeniye) döner.
	List(tenantID string) ([]Check, error)
	// ListAll, TÜM kiracıların check'lerini döner — YALNIZ platform admini için.
	ListAll() ([]Check, error)
	// GetAny, kiracıdan bağımsız id ile tek check döner — YALNIZ platform admini için.
	// Bulunamazsa ErrCheckNotFound.
	GetAny(id string) (Check, error)
	// Resolve, check'i bir sonuca ve residual riske bağlar (VerifiedAt=now). Kiracı-kapsamlı.
	Resolve(tenantID, id string, o Outcome, residual int) (Check, error)
	// Restore, kalıcılıktan check'leri aynen yükler (rehydration; doğrulama yapmaz).
	Restore(cs []Check)
}

// normTenant, kiracı kimliğini karşılaştırma için normalleştirir (casemgmt deseni).
func normTenant(tenantID string) string { return strings.ToLower(strings.TrimSpace(tenantID)) }

func key(tenantID, id string) string { return normTenant(tenantID) + "\x00" + id }

// MemStore, Store'un eşzamanlı-güvenli bellek-içi gerçeklemesidir (test + tek-düğüm).
type MemStore struct {
	mu     sync.RWMutex
	checks map[string]Check
	now    func() time.Time
}

var _ Store = (*MemStore)(nil)

// NewMemStore oluşturur.
func NewMemStore() *MemStore { return &MemStore{checks: map[string]Check{}} }

func (m *MemStore) nowTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now().UTC()
}

// Open, Store arayüzünü gerçekler.
func (m *MemStore) Open(c Check) (Check, error) {
	if strings.TrimSpace(c.TenantID) == "" {
		return Check{}, ErrTenantRequired
	}
	if strings.TrimSpace(c.ID) == "" {
		return Check{}, ErrIDRequired
	}
	if c.Outcome == "" {
		c.Outcome = OutcomePending
	}
	// Baseline verilmemişse bulgunun risk faktörlerinden türet (gerçekleşen risk-azalması
	// hesabının referansı). Residual, doğrulama sonucuna göre Verifier tarafından hesaplanır.
	if c.Baseline == 0 {
		c.Baseline = risk.Score(c.Factors)
	}
	t := m.nowTime()
	if c.OpenedAt.IsZero() {
		c.OpenedAt = t
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks[key(c.TenantID, c.ID)] = c
	return c, nil
}

// Get, Store arayüzünü gerçekler (kiracı-kapsamlı).
func (m *MemStore) Get(tenantID, id string) (Check, error) {
	if strings.TrimSpace(tenantID) == "" {
		return Check{}, ErrTenantRequired
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.checks[key(tenantID, id)]
	if !ok {
		return Check{}, ErrCheckNotFound
	}
	return c, nil
}

// List, Store arayüzünü gerçekler: yalnız verilen kiracının check'leri, OpenedAt sıralı.
func (m *MemStore) List(tenantID string) ([]Check, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrTenantRequired
	}
	nt := normTenant(tenantID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Check, 0)
	for _, c := range m.checks {
		if normTenant(c.TenantID) == nt {
			out = append(out, c)
		}
	}
	sortByOpened(out)
	return out, nil
}

// ListAll, TÜM kiracıların check'lerini döner (platform admini). Kiracı-kapsamı UYGULAMAZ.
func (m *MemStore) ListAll() ([]Check, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Check, 0, len(m.checks))
	for _, c := range m.checks {
		out = append(out, c)
	}
	sortByOpened(out)
	return out, nil
}

// GetAny, kiracıdan bağımsız id ile check döner (platform admini). Bulunamazsa
// ErrCheckNotFound. Çağıran katman yalnız kiracısız (platform) admin için çağırmalıdır.
func (m *MemStore) GetAny(id string) (Check, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.checks {
		if c.ID == id {
			return c, nil
		}
	}
	return Check{}, ErrCheckNotFound
}

// Resolve, Store arayüzünü gerçekler (kiracı-kapsamlı). Bulunamazsa ErrCheckNotFound.
func (m *MemStore) Resolve(tenantID, id string, o Outcome, residual int) (Check, error) {
	if strings.TrimSpace(tenantID) == "" {
		return Check{}, ErrTenantRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(tenantID, id)
	c, ok := m.checks[k]
	if !ok {
		return Check{}, ErrCheckNotFound
	}
	c.Outcome = o
	c.Residual = residual
	c.VerifiedAt = m.nowTime()
	m.checks[k] = c
	return c, nil
}

// Restore, önceden var olan check'leri aynen yükler (rehydration).
func (m *MemStore) Restore(cs []Check) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range cs {
		m.checks[key(c.TenantID, c.ID)] = c
	}
}

// sortByOpened, check'leri OpenedAt'e (eşitlikte ID'ye) göre kararlı sıralar.
func sortByOpened(cs []Check) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].OpenedAt.Equal(cs[j].OpenedAt) {
			return cs[i].ID < cs[j].ID
		}
		return cs[i].OpenedAt.Before(cs[j].OpenedAt)
	})
}
