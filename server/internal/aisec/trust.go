package aisec

// trust.go — P0-A: Agent Telemetry Trust. Agent-davranış gözlemleri Agent Causality
// Graph'a girmeden ÖNCE KRİPTOGRAFİK olarak doğrulanır: imza + tenant bağı + sequence +
// anti-replay + timestamp tazeliği. Böylece sahte/tahrif/replay telemetri (KUT-AI-SEC:
// fake agent telemetry / telemetry tampering) graf'ı zehirleyemez. FAIL-CLOSED: herhangi
// bir kontrol geçmezse DENY. Enforcement yok; yalnız kabul/ret (gözlem DATA'dır).

import (
	"crypto/ed25519"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Telemetri-güven ret sentinel'leri (her biri bir DoD kabul kriterine karşılık gelir).
var (
	ErrUnknownAgent     = errors.New("aisec: bilinmeyen agent (kimlik kayıtlı değil)")
	ErrTenantMismatch   = errors.New("aisec: tenant uyuşmuyor")
	ErrExpiredTimestamp = errors.New("aisec: timestamp taze değil (pencere dışı)")
	ErrBadSignature     = errors.New("aisec: imza geçersiz")
	ErrReplay           = errors.New("aisec: replay (nonce daha önce görüldü)")
	ErrSequenceRollback = errors.New("aisec: sequence gerilemesi (monoton değil)")
)

// SignedObservation, kriptografik imzalı bir agent telemetri gözlemidir. Payload,
// kanonik serileştirilmiş gözlemdir (düğüm+kenar); imza aşağıdaki tüm alanları kapsar.
type SignedObservation struct {
	AgentID   string
	TenantID  string
	Sequence  uint64
	Timestamp time.Time
	Nonce     string
	Payload   []byte
	Signature []byte
}

// SigningBytes, imzalanacak/doğrulanacak KANONİK baytları üretir. Üretici (agent) ve
// doğrulayıcı (sunucu) aynı formu üretmelidir; alan sırası ve ayraç sabittir.
func SigningBytes(o SignedObservation) []byte {
	var b []byte
	add := func(s string) { b = append(b, s...); b = append(b, 0x1f) }
	add(o.AgentID)
	add(o.TenantID)
	add(strconv.FormatUint(o.Sequence, 10))
	add(strconv.FormatInt(o.Timestamp.UnixNano(), 10))
	add(o.Nonce)
	b = append(b, o.Payload...)
	return b
}

// AgentKeyRegistry, agentID → (ed25519 açık anahtar + tenant) eşlemesidir (kimlik kaydı).
// Kimlik model çıktısından ÇIKARSANMAZ (INV-AG-007) — kayıt otoritatiftir.
type AgentKeyRegistry interface {
	Lookup(agentID string) (pub ed25519.PublicKey, tenant string, ok bool)
}

// MemKeyRegistry, AgentKeyRegistry'nin bellek-içi gerçekleştirimidir.
type MemKeyRegistry struct {
	mu   sync.RWMutex
	keys map[string]struct {
		pub    ed25519.PublicKey
		tenant string
	}
}

// NewMemKeyRegistry oluşturur.
func NewMemKeyRegistry() *MemKeyRegistry {
	return &MemKeyRegistry{keys: map[string]struct {
		pub    ed25519.PublicKey
		tenant string
	}{}}
}

// Register, bir agent kimliğini (açık anahtar + tenant) kaydeder.
func (r *MemKeyRegistry) Register(agentID string, pub ed25519.PublicKey, tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[agentID] = struct {
		pub    ed25519.PublicKey
		tenant string
	}{pub, tenant}
}

// Lookup, AgentKeyRegistry'yi gerçekler.
func (r *MemKeyRegistry) Lookup(agentID string) (ed25519.PublicKey, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.keys[agentID]
	return e.pub, e.tenant, ok
}

// TrustVerifier, imzalı gözlemleri doğrular (fail-closed). Eşzamanlı kullanım güvenlidir.
// Anti-replay iki katmanlıdır: sequence MONOTON artan olmalı (rollback+eski-replay'i
// reddeder) ve nonce daha önce görülmemiş olmalı (aynı-sequence yeniden-imzalamayı reddeder).
type TrustVerifier struct {
	reg    AgentKeyRegistry
	now    func() time.Time
	window time.Duration

	mu      sync.Mutex
	lastSeq map[string]uint64
	seen    map[string]bool
}

// NewTrustVerifier oluşturur. now nil ise time.Now; window<=0 ise 5dk (timestamp tazeliği).
func NewTrustVerifier(reg AgentKeyRegistry, now func() time.Time, window time.Duration) *TrustVerifier {
	if now == nil {
		now = time.Now
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &TrustVerifier{reg: reg, now: now, window: window, lastSeq: map[string]uint64{}, seen: map[string]bool{}}
}

// Verify, gözlemi doğrular. nil → KABUL (ve durum güncellenir); aksi halde spesifik DENY
// sentinel'i. Doğrulama SIRASI: kimlik → tenant → tazelik → imza → sequence → nonce.
// Sıra önemlidir: durum-değiştiren (sequence/nonce kaydı) yalnız imza doğrulandıktan
// sonra yapılır (imzasız bir istek replay-durumunu kirletemez).
func (v *TrustVerifier) Verify(o SignedObservation) error {
	pub, tenant, ok := v.reg.Lookup(o.AgentID)
	if !ok {
		return ErrUnknownAgent
	}
	if o.TenantID == "" || normTenant(o.TenantID) != normTenant(tenant) {
		return ErrTenantMismatch
	}
	now := v.now()
	if d := now.Sub(o.Timestamp); d > v.window || d < -v.window {
		return ErrExpiredTimestamp
	}
	if !ed25519.Verify(pub, SigningBytes(o), o.Signature) {
		return ErrBadSignature
	}
	// İmza geçerli → anti-replay durumunu tek kilit altında kontrol et + güncelle.
	v.mu.Lock()
	defer v.mu.Unlock()
	if o.Sequence <= v.lastSeq[o.AgentID] {
		return ErrSequenceRollback
	}
	if o.Nonce == "" || v.seen[o.Nonce] {
		return ErrReplay
	}
	v.lastSeq[o.AgentID] = o.Sequence
	v.seen[o.Nonce] = true
	return nil
}
