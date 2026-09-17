// Package authtoken, YÖNETİLEN API token'ları sağlar: statik ortam-değişkeni
// Bearer token'larının aksine oluşturma/doğrulama/İPTAL ve SÜRE (expiry) + KAPSAM
// (scope) destekler. metrics ve ingest uçları için kullanılır. Sırlar yalnız SHA-256
// özeti olarak saklanır (düz sır bir kez, oluşturmada döner). Bağımlılıksız.
package authtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Kapsamlar: hangi uca yetki verdiği.
const (
	ScopeMetrics = "metrics"
	ScopeIngest  = "ingest"
)

// ErrNotFound, iptal edilecek token bulunamadığında döner.
var ErrNotFound = errors.New("authtoken: token bulunamadı")

// Token, bir yönetilen token'ın meta verisidir (SIR İÇERMEZ — yalnız özet dahili).
type Token struct {
	ID         string     `json:"id"`
	Scope      string     `json:"scope"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"` // nil => süresiz
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Store, yönetilen token'ları saklar. Verify sabit-zamanlı özet karşılaştırması
// yapmalı ve LastUsedAt'i güncellemelidir.
type Store interface {
	// Create, verilen kapsam için yeni bir token üretir; token id'sini ve DÜZ SIRRI
	// (yalnız burada döner) verir. ttl<=0 => süresiz.
	Create(scope string, ttl time.Duration) (id, secret string, err error)
	// Verify, sunulan sır bu kapsamda geçerli (iptal edilmemiş, süresi dolmamış) bir
	// token'a aitse true döner ve LastUsedAt'i günceller.
	Verify(scope, presented string) bool
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
	tok := Token{ID: id, Scope: scope, CreatedAt: t}
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
	if presented == "" {
		return false
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
			return true
		}
	}
	return false
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
