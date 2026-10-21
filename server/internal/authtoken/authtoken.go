// Package authtoken, YÖNETİLEN API token'ları sağlar: statik ortam-değişkeni
// Bearer token'larının aksine oluşturma/doğrulama/İPTAL ve SÜRE (expiry) + KAPSAM
// (scope) + (ingest için) KİRACI BAĞI destekler. metrics ve ingest uçları için
// kullanılır. Sırlar yalnız SHA-256 özeti olarak saklanır (düz sır bir kez,
// oluşturmada döner). Yalnız küçük bir iç paket (tenant) kullanır.
package authtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"kut.corp/suite/server/internal/tenant"
)

// Kapsamlar: hangi uca yetki verdiği.
const (
	ScopeMetrics = "metrics"
	ScopeIngest  = "ingest"
)

// ErrNotFound, iptal edilecek token bulunamadığında döner.
var ErrNotFound = errors.New("authtoken: token bulunamadı")

// ErrInvalidTenantBinding, token'a geçersiz bir kiracı bağı verildiğinde döner: biçim
// hatalı kiracı, ya da kiracı-bağı kabul etmeyen bir kapsam (metrics filo-geneli okur).
var ErrInvalidTenantBinding = errors.New("authtoken: geçersiz kiracı bağı")

// ValidateTenantBinding, bir token'a bağlanmak istenen kiracıyı doğrular ve normalize eder
// (kırp + küçük harf + [a-z0-9-], 1-63). Boş kiracı boş döner (kiracısız = legacy/platform).
// Yalnız ingest kapsamı kiracıya bağlanabilir: metrics token'ı filo-geneli özet okuduğundan
// kiracı bağı taşıyamaz (fail-closed). Kiracı ASLA istemci verisinden türetilmez; çağıran
// (platform admini) sunucu-tarafında verir.
func ValidateTenantBinding(scope, tenantID string) (string, error) {
	if tenantID == "" {
		return "", nil
	}
	if scope != ScopeIngest {
		return "", ErrInvalidTenantBinding
	}
	id, err := tenant.Normalize(tenantID)
	if err != nil {
		return "", ErrInvalidTenantBinding
	}
	return string(id), nil
}

// Token, bir yönetilen token'ın meta verisidir (SIR İÇERMEZ — yalnız özet dahili).
type Token struct {
	ID         string     `json:"id"`
	Scope      string     `json:"scope"`
	Tenant     string     `json:"tenant,omitempty"` // ingest token'ının bağlı kiracısı (boş = legacy/kiracısız)
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"` // nil => süresiz
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Store, yönetilen token'ları saklar. Verify sabit-zamanlı özet karşılaştırması
// yapmalı ve LastUsedAt'i güncellemelidir.
type Store interface {
	// Create, verilen kapsam için yeni KİRACISIZ bir token üretir; token id'sini ve DÜZ
	// SIRRI (yalnız burada döner) verir. ttl<=0 => süresiz.
	Create(scope string, ttl time.Duration) (id, secret string, err error)
	// CreateForTenant, token'ı oluşturma anında bir kiracıya BAĞLAR (yalnız ingest kapsamı;
	// bkz. ValidateTenantBinding). Bağ sunucu-tarafıdır ve sonradan değişmez; bu token ile
	// alınan olaylar o kiracıyla damgalanır.
	CreateForTenant(scope, tenantID string, ttl time.Duration) (id, secret string, err error)
	// Verify, sunulan sır bu kapsamda geçerli (iptal edilmemiş, süresi dolmamış) KİRACISIZ
	// bir token'a aitse true döner ve LastUsedAt'i günceller. Kiracıya bağlı token'lar
	// burada KABUL EDİLMEZ (kiracı-kör doğrulama kiracı bağını yok sayardı): onlar için
	// VerifyTenant kullanılır.
	Verify(scope, presented string) bool
	// VerifyTenant, Verify gibi doğrular ve token'ın bağlı kiracısını da döner (kiracısız
	// token için boş). ok=false => geçersiz.
	VerifyTenant(scope, presented string) (tenantID string, ok bool)
	// Revoke, token'ı iptal eder (artık doğrulanmaz).
	Revoke(id string) error
	// List, verilen kapsamdaki token'ları (sır olmadan) döner. scope boşsa tümü.
	List(scope string) ([]Token, error)
}

// HashSecret, bir düz sırrın saklanan SHA-256 hex özetini döner.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// NewSecret, 32 baytlık kriptografik rastgele bir sır (hex) üretir.
func NewSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// record, MemStore'da tutulan iç kayıttır (özet + meta).
type record struct {
	hash string
	tok  Token
}

// MemStore, bellek-içi yönetilen token deposudur (demo / DB'siz).
type MemStore struct {
	mu   sync.Mutex
	byID map[string]*record
	now  func() time.Time
}

// NewMemStore, boş bir bellek-içi depo kurar. now nil => time.Now.
func NewMemStore(now func() time.Time) *MemStore {
	if now == nil {
		now = time.Now
	}
	return &MemStore{byID: map[string]*record{}, now: now}
}

func (s *MemStore) Create(scope string, ttl time.Duration) (string, string, error) {
	return s.CreateForTenant(scope, "", ttl)
}

func (s *MemStore) CreateForTenant(scope, tenantID string, ttl time.Duration) (string, string, error) {
	tenantID, err := ValidateTenantBinding(scope, tenantID)
	if err != nil {
		return "", "", err
	}
	secret, err := NewSecret()
	if err != nil {
		return "", "", err
	}
	idb, err := NewSecret()
	if err != nil {
		return "", "", err
	}
	id := idb[:24]
	t := s.now().UTC()
	tok := Token{ID: id, Scope: scope, Tenant: tenantID, CreatedAt: t}
	if ttl > 0 {
		exp := t.Add(ttl)
		tok.ExpiresAt = &exp
	}
	s.mu.Lock()
	s.byID[id] = &record{hash: HashSecret(secret), tok: tok}
	s.mu.Unlock()
	return id, secret, nil
}

func (s *MemStore) Verify(scope, presented string) bool {
	t, ok := s.VerifyTenant(scope, presented)
	return ok && t == ""
}

func (s *MemStore) VerifyTenant(scope, presented string) (string, bool) {
	if presented == "" {
		return "", false
	}
	want := HashSecret(presented)
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.byID {
		if r.tok.Scope != scope || r.tok.RevokedAt != nil {
			continue
		}
		if r.tok.ExpiresAt != nil && now.After(*r.tok.ExpiresAt) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(r.hash), []byte(want)) == 1 {
			r.tok.LastUsedAt = &now
			return r.tok.Tenant, true
		}
	}
	return "", false
}

func (s *MemStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if r.tok.RevokedAt == nil {
		t := s.now().UTC()
		r.tok.RevokedAt = &t
	}
	return nil
}

func (s *MemStore) List(scope string) ([]Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Token, 0, len(s.byID))
	for _, r := range s.byID {
		if scope == "" || r.tok.Scope == scope {
			out = append(out, r.tok)
		}
	}
	return out, nil
}
