// Package detbits, ÇOK-AŞAMALI tespit için host-kapsamlı, SÜRELİ (TTL) durum
// bitleri sağlar (IDS `flowbits`/`xbits` kavramının uç-nokta uyarlaması).
// Bir tespit kuralı eşleşince adlandırılmış bir bit KURAR (Set); başka bir kural
// bu biti ÖN-KOŞUL olarak arar (Require) ve yalnız bit kuruluyken alarma dönüşür.
// Böylece "önce keşif, sonra yatay hareket" gibi AŞAMALI saldırılar, tek bir olaya
// değil DİZİYE bakılarak yüksek-güvenle yakalanır; tek başına zararsız görünen
// ikinci aşama, birinci aşama yakın zamanda görülmedikçe gürültü yapmaz.
//
// Durum bellek-içidir (threshold/correlate ile aynı desen) ve tespit motorunun
// DIŞINDA tutulur — motor atomik hot-reload ile değişse de bitler korunur.
// Bağımlılıksız; eşzamanlı-güvenli; süresi dolan bitler tembel + sınırlı budanır.
package detbits

import (
	"sync"
	"time"
)

// Store, (scope|bit) → son-geçerlilik anı eşlemesi tutar.
type Store struct {
	mu   sync.Mutex
	bits map[string]time.Time
	now  func() time.Time
	max  int // izlenen bit üst sınırı (bellek sınırlama)
}

// New, boş bir depo kurar. now nil → time.Now.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{bits: map[string]time.Time{}, now: now, max: 200_000}
}

// key, scope ve bit adını çakışmasız birleştirir (NUL ayraç: ad/scope'ta geçmez).
func key(scope, bit string) string { return scope + "\x00" + bit }

// Set, bir biti scope için ttl süreliğine kurar. ttl<=0 → 1 saat (varsayılan).
// Boş bit adı yok sayılır.
func (s *Store) Set(scope, bit string, ttl time.Duration) {
	if bit == "" {
		return
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	now := s.now()
	s.mu.Lock()
	s.pruneLocked(now)
	s.bits[key(scope, bit)] = now.Add(ttl)
	s.mu.Unlock()
}

// IsSet, bit scope için kurulu VE süresi dolmamışsa true döner. Süresi dolmuşsa
// tembel siler.
func (s *Store) IsSet(scope, bit string) bool {
	if bit == "" {
		return false
	}
	k := key(scope, bit)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.bits[k]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(s.bits, k)
		return false
	}
	return true
}

// AllSet, verilen bitlerin TÜMÜ kuruluysa true döner (RequireBits ön-koşulu).
// Boş liste → true (koşul yok). Boş bit adları atlanır.
func (s *Store) AllSet(scope string, bits []string) bool {
	for _, b := range bits {
		if b == "" {
			continue
		}
		if !s.IsSet(scope, b) {
			return false
		}
	}
	return true
}

// NoneSet, verilen bitlerin HİÇBİRİ kurulu değilse true döner (RequireNot ön-koşulu;
// IDS flowbits:isnotset muadili). Boş liste → true. Boş bit adları atlanır.
func (s *Store) NoneSet(scope string, bits []string) bool {
	for _, b := range bits {
		if b == "" {
			continue
		}
		if s.IsSet(scope, b) {
			return false
		}
	}
	return true
}

// pruneLocked, bit sayısı sınırı aşınca süresi dolmuş bitleri budar. Kilit
// çağıran tarafından tutulur.
func (s *Store) pruneLocked(now time.Time) {
	if len(s.bits) <= s.max {
		return
	}
	for k, exp := range s.bits {
		if now.After(exp) {
			delete(s.bits, k)
		}
	}
}

// TrackedCount, o an tutulan bit sayısını döner (gözlem/test).
func (s *Store) TrackedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bits)
}
