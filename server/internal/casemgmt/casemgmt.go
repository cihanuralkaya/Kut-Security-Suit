// Package casemgmt, SOC (Güvenlik Operasyon Merkezi) olay/vaka yönetim
// modelini gerçekler: vNext mimarisinin "SOC Command Center" bileşeninin P2
// çekirdeğidir (bkz. docs/ARCHITECTURE-vNext.md).
//
// Bir vaka (Case), bir durum makinesi (Open→Investigating→Contained→Closed,
// ayrıca Closed'dan yeniden açma), sahiplik, ilişkili varlıklar/kullanıcılar,
// MITRE ATT&CK teknikleri, delil referansları ve DEĞİŞMEZ (append-only) bir
// olay zaman çizelgesi içerir. Zaman çizelgesi, delil zinciri
// (chain-of-custody) ve denetim izi için asla düzenlenmez veya silinmez;
// her mutasyon (durum geçişi, atama, ekleme) otomatik olarak değişmez bir
// CaseEvent üretir.
//
// Paket saf Go'dur; go.mod'a hiçbir dış bağımlılık eklemez. Kiracı izolasyonu
// paket-içi basit bir normalizasyonla sağlanır (dış iam bağımlılığı yoktur):
// bir kiracının vakaları başka bir kiracıya görünmez.
package casemgmt

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity, bir vakanın önem derecesidir.
type Severity string

// Desteklenen önem dereceleri (artan ciddiyet sırasına yakın).
const (
	// SeverityLow, düşük önem derecesidir.
	SeverityLow Severity = "LOW"
	// SeverityMedium, orta önem derecesidir.
	SeverityMedium Severity = "MEDIUM"
	// SeverityHigh, yüksek önem derecesidir.
	SeverityHigh Severity = "HIGH"
	// SeverityCritical, kritik önem derecesidir.
	SeverityCritical Severity = "CRITICAL"
)

// Status, bir vakanın yaşam döngüsü durumudur (durum makinesi düğümü).
type Status string

// Vaka yaşam döngüsü durumları.
const (
	// StatusOpen, yeni açılmış, henüz incelenmeye başlanmamış vakadır.
	StatusOpen Status = "OPEN"
	// StatusInvestigating, aktif olarak incelenen vakadır.
	StatusInvestigating Status = "INVESTIGATING"
	// StatusContained, tehdidin sınırlandığı (containment) vakadır.
	StatusContained Status = "CONTAINED"
	// StatusClosed, kapatılmış vakadır (yeniden açılabilir).
	StatusClosed Status = "CLOSED"
)

// AttachKind, Attach ile bir vakaya eklenebilecek referans türüdür.
type AttachKind string

// Ekleme (attach) türleri.
const (
	// AttachAsset, ilişkili bir varlık (cihaz/host) ekler.
	AttachAsset AttachKind = "asset"
	// AttachUser, ilişkili bir kullanıcı ekler.
	AttachUser AttachKind = "user"
	// AttachMITRE, bir MITRE ATT&CK tekniği (ör. T1059) ekler.
	AttachMITRE AttachKind = "mitre"
	// AttachEvidence, bir delil referansı (ör. artefakt URI'si) ekler.
	AttachEvidence AttachKind = "evidence"
)

// Olay zaman çizelgesine yazılan mutasyon türleri (CaseEvent.Kind).
const (
	// KindCreated, vakanın oluşturulduğunu belirtir.
	KindCreated = "created"
	// KindTransition, bir durum geçişini belirtir.
	KindTransition = "transition"
	// KindAssign, sahiplik atamasını belirtir.
	KindAssign = "assign"
	// KindAttach, bir referans eklemesini belirtir.
	KindAttach = "attach"
	// KindNote, serbest bir not girdisini belirtir.
	KindNote = "note"
)

// Vaka yönetimi hataları.
var (
	// ErrInvalidTransition, geçersiz bir durum geçişi istendiğinde döner.
	// Bu durumda vakanın durumu DEĞİŞTİRİLMEZ ve zaman çizelgesine yazılmaz
	// (fail-closed).
	ErrInvalidTransition = errors.New("casemgmt: geçersiz durum geçişi")
	// ErrCaseExists, verilen id ile zaten bir vaka varsa döner.
	ErrCaseExists = errors.New("casemgmt: vaka zaten var")
	// ErrCaseNotFound, istenen vaka bulunamazsa (veya kiracı eşleşmezse) döner.
	ErrCaseNotFound = errors.New("casemgmt: vaka bulunamadı")
	// ErrTenantRequired, kiracı kimliği boş verildiğinde döner.
	ErrTenantRequired = errors.New("casemgmt: kiracı kimliği gerekli")
	// ErrIDRequired, vaka kimliği boş verildiğinde döner.
	ErrIDRequired = errors.New("casemgmt: vaka kimliği gerekli")
	// ErrUnknownAttachKind, tanınmayan bir ekleme türü verildiğinde döner.
	ErrUnknownAttachKind = errors.New("casemgmt: tanınmayan ekleme türü")
	// ErrInvalidStatus, geçiş hedefi bilinen bir durum değilse döner.
	ErrInvalidStatus = errors.New("casemgmt: bilinmeyen durum")
)

// CaseEvent, zaman çizelgesindeki DEĞİŞMEZ (append-only) bir girdidir:
// kim (Actor), ne (Kind), ne zaman (At) ve serbest bir açıklama (Note).
// Bir kez yazıldıktan sonra asla düzenlenmez veya silinmez.
type CaseEvent struct {
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	Kind  string    `json:"kind"`
	Note  string    `json:"note"`
}

// Case, bir SOC vakasıdır. Timeline dışa döndürülürken kopyalanır; çağıran
// tarafın değiştirmesi depodaki değişmez izi etkilemez.
type Case struct {
	ID           string      `json:"id"`
	TenantID     string      `json:"tenant_id"`
	Title        string      `json:"title"`
	Severity     Severity    `json:"severity"`
	Status       Status      `json:"status"`
	Owner        string      `json:"owner"`
	Assets       []string    `json:"assets,omitempty"`
	Users        []string    `json:"users,omitempty"`
	MITRE        []string    `json:"mitre,omitempty"`
	EvidenceRefs []string    `json:"evidence_refs,omitempty"`
	Timeline     []CaseEvent `json:"timeline"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

// Store, vaka yaşam döngüsünü yöneten depolama arayüzüdür. Tüm işlemler
// kiracı-kapsamlıdır: bir kiracının vakaları başka bir kiracıya görünmez.
type Store interface {
	// Create, yeni bir vaka oluşturur ve zaman çizelgesine bir "created"
	// girdisi yazar. id zaten varsa ErrCaseExists döner.
	Create(c Case) (Case, error)
	// Get, verilen kiracıya ait vakayı döndürür. Kiracı eşleşmezse veya vaka
	// yoksa ErrCaseNotFound döner.
	Get(tenantID, id string) (Case, error)
	// List, verilen kiracıya ait tüm vakaları CreatedAt'e göre sıralı döndürür.
	List(tenantID string) ([]Case, error)
	// Transition, vakayı yeni bir duruma geçirir. Yalnız GEÇERLİ geçişlere
	// izin verilir; geçersizde ErrInvalidTransition döner, durum DEĞİŞMEZ ve
	// zaman çizelgesine yazılmaz (fail-closed).
	Transition(tenantID, id, actor string, to Status, note string) (Case, error)
	// AddEvent, zaman çizelgesine serbest bir değişmez girdi ekler.
	AddEvent(tenantID, id string, ev CaseEvent) (Case, error)
	// Assign, vakanın sahibini değiştirir ve denetim izine yazar.
	Assign(tenantID, id, actor, owner string) (Case, error)
	// Attach, vakaya bir referans (asset/user/mitre/evidence) ekler ve denetim
	// izine yazar. Aynı referans yinelenmez (idempotent ekleme).
	Attach(tenantID, id, actor string, kind AttachKind, ref string) (Case, error)
}

// allowedTransitions, durum makinesinin GEÇERLİ geçiş tablosudur.
//
//	OPEN          → INVESTIGATING, CLOSED
//	INVESTIGATING → CONTAINED, CLOSED, OPEN
//	CONTAINED     → CLOSED, INVESTIGATING
//	CLOSED        → OPEN (yeniden açma)
//
// Tabloda olmayan her geçiş (ve aynı duruma geçiş) geçersizdir.
var allowedTransitions = map[Status]map[Status]bool{
	StatusOpen: {
		StatusInvestigating: true,
		StatusClosed:        true,
	},
	StatusInvestigating: {
		StatusContained: true,
		StatusClosed:    true,
		StatusOpen:      true,
	},
	StatusContained: {
		StatusClosed:        true,
		StatusInvestigating: true,
	},
	StatusClosed: {
		StatusOpen: true,
	},
}

// knownStatus, verilen durumun bilinen bir yaşam döngüsü düğümü olup
// olmadığını bildirir.
func knownStatus(s Status) bool {
	switch s {
	case StatusOpen, StatusInvestigating, StatusContained, StatusClosed:
		return true
	default:
		return false
	}
}

// canTransition, from durumundan to durumuna geçişin geçerli olup olmadığını
// bildirir. Bu, durum makinesinin tek doğruluk kaynağıdır.
func canTransition(from, to Status) bool {
	return allowedTransitions[from][to]
}

// NormTenant, kiracı kimliğini karşılaştırma için normalleştirir: baştaki/
// sondaki boşlukları kırpar ve küçük harfe çevirir. iam paketindeki desene
// benzer, ancak kasten bağımsızdır (bu paket dış bağımlılık eklemez).
func NormTenant(tenantID string) string {
	return strings.ToLower(strings.TrimSpace(tenantID))
}

// MemStore, Store arayüzünün eşzamanlı-güvenli, bellek-içi gerçeklemesidir.
// Test ve tek-düğüm kurulumlar için uygundur. Vakalar (kiracı, id) çiftiyle
// anahtarlanır; böylece farklı kiracılar aynı ham id'yi yeniden kullanabilir.
type MemStore struct {
	mu    sync.RWMutex
	cases map[string]Case
	// now, zaman damgaları için enjekte edilebilir saat (nil ise time.Now).
	now func() time.Time
}

// NewMemStore, boş bir bellek-içi depo oluşturur.
func NewMemStore() *MemStore {
	return &MemStore{cases: make(map[string]Case)}
}

// Restore, önceden var olan vakaları depoya AYNEN yükler (doğrulama/sıfırlama
// yapmadan, zaman çizelgesini olduğu gibi koruyarak). Kalıcılıktan (DB) yeniden
// canlandırma (rehydration) için kullanılır — Create'ten farkı: durum/timeline
// sıfırlanmaz. Aynı anahtar tekrar gelirse üzerine yazar.
func (m *MemStore) Restore(cases []Case) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range cases {
		m.cases[key(c.TenantID, c.ID)] = clone(c)
	}
}

// nowTime, enjekte edilmiş saati veya time.Now'u (UTC) döndürür.
func (m *MemStore) nowTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now().UTC()
}

// key, iç harita anahtarını (normalleştirilmiş kiracı + id) üretir.
func key(tenantID, id string) string {
	return NormTenant(tenantID) + "\x00" + id
}

// clone, bir vakanın dilimlerini derin kopyalar; böylece dışarıya verilen
// kopyanın değiştirilmesi depodaki değişmez kaydı etkilemez.
func clone(c Case) Case {
	c.Assets = append([]string(nil), c.Assets...)
	c.Users = append([]string(nil), c.Users...)
	c.MITRE = append([]string(nil), c.MITRE...)
	c.EvidenceRefs = append([]string(nil), c.EvidenceRefs...)
	c.Timeline = append([]CaseEvent(nil), c.Timeline...)
	return c
}

// Create, Store arayüzünü gerçekler.
func (m *MemStore) Create(c Case) (Case, error) {
	if strings.TrimSpace(c.TenantID) == "" {
		return Case{}, ErrTenantRequired
	}
	if strings.TrimSpace(c.ID) == "" {
		return Case{}, ErrIDRequired
	}
	if c.Severity == "" {
		c.Severity = SeverityMedium
	}
	// Oluşturmada durum daima OPEN'dır (yaşam döngüsünün girişi).
	c.Status = StatusOpen

	m.mu.Lock()
	defer m.mu.Unlock()

	k := key(c.TenantID, c.ID)
	if _, ok := m.cases[k]; ok {
		return Case{}, ErrCaseExists
	}

	t := m.nowTime()
	c.CreatedAt = t
	c.UpdatedAt = t
	// Değişmez zaman çizelgesini oluşturma girdisiyle başlat.
	c.Timeline = []CaseEvent{{
		At:    t,
		Actor: c.Owner,
		Kind:  KindCreated,
		Note:  "vaka oluşturuldu",
	}}
	m.cases[k] = clone(c)
	return clone(c), nil
}

// getLocked, kilit altında vakayı bulur (çağıran kilidi tutmalıdır).
func (m *MemStore) getLocked(tenantID, id string) (Case, string, error) {
	if strings.TrimSpace(tenantID) == "" {
		return Case{}, "", ErrTenantRequired
	}
	k := key(tenantID, id)
	c, ok := m.cases[k]
	if !ok {
		return Case{}, "", ErrCaseNotFound
	}
	return c, k, nil
}

// Get, Store arayüzünü gerçekler.
func (m *MemStore) Get(tenantID, id string) (Case, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, _, err := m.getLocked(tenantID, id)
	if err != nil {
		return Case{}, err
	}
	return clone(c), nil
}

// List, Store arayüzünü gerçekler: yalnız verilen kiracının vakalarını,
// CreatedAt'e (eşitlikte ID'ye) göre sıralı döndürür. Kiracı izolasyonu
// burada uygulanır.
func (m *MemStore) List(tenantID string) ([]Case, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrTenantRequired
	}
	nt := NormTenant(tenantID)

	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Case, 0)
	for _, c := range m.cases {
		if NormTenant(c.TenantID) == nt {
			out = append(out, clone(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// appendEvent, kilit altında değişmez bir olay ekler, UpdatedAt'i günceller ve
// depoyu yeniden yazar. Zaman çizelgesi yalnız buradan büyür (append-only).
func (m *MemStore) appendEvent(k string, c Case, ev CaseEvent, at time.Time) Case {
	c.Timeline = append(c.Timeline, ev)
	c.UpdatedAt = at
	m.cases[k] = clone(c)
	return clone(c)
}

// Transition, Store arayüzünü gerçekler. Geçersiz geçişte ErrInvalidTransition
// döner; durum DEĞİŞMEZ ve zaman çizelgesine hiçbir şey yazılmaz (fail-closed).
func (m *MemStore) Transition(tenantID, id, actor string, to Status, note string) (Case, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, k, err := m.getLocked(tenantID, id)
	if err != nil {
		return Case{}, err
	}
	if !knownStatus(to) {
		return Case{}, ErrInvalidStatus
	}
	if !canTransition(c.Status, to) {
		// Fail-closed: durum korunur, zaman çizelgesi yazılmaz.
		return Case{}, ErrInvalidTransition
	}

	from := c.Status
	c.Status = to
	at := m.nowTime()
	ev := CaseEvent{
		At:    at,
		Actor: actor,
		Kind:  KindTransition,
		Note:  transitionNote(from, to, note),
	}
	return m.appendEvent(k, c, ev, at), nil
}

// transitionNote, denetim için okunabilir bir geçiş notu üretir.
func transitionNote(from, to Status, note string) string {
	base := string(from) + " → " + string(to)
	if strings.TrimSpace(note) == "" {
		return base
	}
	return base + ": " + note
}

// AddEvent, Store arayüzünü gerçekler: zaman çizelgesine serbest, değişmez bir
// girdi ekler. At boşsa depo saati kullanılır; Kind boşsa KindNote atanır.
func (m *MemStore) AddEvent(tenantID, id string, ev CaseEvent) (Case, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, k, err := m.getLocked(tenantID, id)
	if err != nil {
		return Case{}, err
	}
	at := ev.At
	if at.IsZero() {
		at = m.nowTime()
		ev.At = at
	}
	if strings.TrimSpace(ev.Kind) == "" {
		ev.Kind = KindNote
	}
	return m.appendEvent(k, c, ev, at), nil
}

// Assign, Store arayüzünü gerçekler: sahibi değiştirir ve denetim izine yazar.
func (m *MemStore) Assign(tenantID, id, actor, owner string) (Case, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, k, err := m.getLocked(tenantID, id)
	if err != nil {
		return Case{}, err
	}
	prev := c.Owner
	c.Owner = owner
	at := m.nowTime()
	ev := CaseEvent{
		At:    at,
		Actor: actor,
		Kind:  KindAssign,
		Note:  "sahip: " + emptyDash(prev) + " → " + emptyDash(owner),
	}
	return m.appendEvent(k, c, ev, at), nil
}

// emptyDash, boş dizeyi "-" ile gösterir (okunabilir denetim notu için).
func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// Attach, Store arayüzünü gerçekler: ilgili dilime bir referans ekler (yinelenmez)
// ve denetim izine yazar. Tanınmayan tür ErrUnknownAttachKind döndürür.
func (m *MemStore) Attach(tenantID, id, actor string, kind AttachKind, ref string) (Case, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, k, err := m.getLocked(tenantID, id)
	if err != nil {
		return Case{}, err
	}

	added := false
	switch kind {
	case AttachAsset:
		c.Assets, added = appendUnique(c.Assets, ref)
	case AttachUser:
		c.Users, added = appendUnique(c.Users, ref)
	case AttachMITRE:
		c.MITRE, added = appendUnique(c.MITRE, ref)
	case AttachEvidence:
		c.EvidenceRefs, added = appendUnique(c.EvidenceRefs, ref)
	default:
		return Case{}, ErrUnknownAttachKind
	}

	if !added {
		// Yinelenen ekleme: durum değişmez, ancak denetim izine yine de
		// işlemin gerçekleştiği yazılır (idempotent ama izlenebilir).
		return clone(c), nil
	}

	at := m.nowTime()
	ev := CaseEvent{
		At:    at,
		Actor: actor,
		Kind:  KindAttach,
		Note:  string(kind) + ": " + ref,
	}
	return m.appendEvent(k, c, ev, at), nil
}

// appendUnique, ref dilimde yoksa ekler. Eklenip eklenmediğini de bildirir.
func appendUnique(s []string, ref string) ([]string, bool) {
	for _, v := range s {
		if v == ref {
			return s, false
		}
	}
	return append(s, ref), true
}

// AllowedTargets, verilen durumdan gidilebilecek GEÇERLİ hedef durumları
// (sıralı) döndürür. Kullanıcı arayüzleri geçiş düğmelerini bununla üretebilir.
func AllowedTargets(from Status) []Status {
	targets := make([]Status, 0, len(allowedTransitions[from]))
	for to := range allowedTransitions[from] {
		targets = append(targets, to)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	return targets
}

// Derleme-zamanı güvencesi: MemStore, Store arayüzünü karşılar.
var _ Store = (*MemStore)(nil)
