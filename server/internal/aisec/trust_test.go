package aisec

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func mkSigned(agentID, tenant string, seq uint64, ts time.Time, nonce string, payload []byte, priv ed25519.PrivateKey) SignedObservation {
	o := SignedObservation{AgentID: agentID, TenantID: tenant, Sequence: seq, Timestamp: ts, Nonce: nonce, Payload: payload}
	o.Signature = ed25519.Sign(priv, SigningBytes(o))
	return o
}

// TestTrustVerifier, P0-A kabul kriterlerini (DoD) uçtan uca doğrular.
func TestTrustVerifier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	reg := NewMemKeyRegistry()
	reg.Register("agent-1", pub, "acme")
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	v := NewTrustVerifier(reg, func() time.Time { return now }, time.Minute)
	payload := []byte(`{"nodes":[]}`)

	// 1) Geçerli imzalı telemetri → KABUL.
	if err := v.Verify(mkSigned("agent-1", "acme", 1, now, "n1", payload, priv)); err != nil {
		t.Fatalf("geçerli telemetri kabul edilmeli: %v", err)
	}
	// 2) İkinci geçerli (seq artan, yeni nonce) → KABUL.
	if err := v.Verify(mkSigned("agent-1", "acme", 2, now, "n2", payload, priv)); err != nil {
		t.Fatalf("ikinci geçerli telemetri kabul edilmeli: %v", err)
	}

	// 3) Geçersiz imza (payload imzadan sonra değişti) → DENY.
	bad := mkSigned("agent-1", "acme", 3, now, "n3", payload, priv)
	bad.Payload = []byte(`{"nodes":[{"id":"x"}]}`) // imza artık uyumsuz
	if err := v.Verify(bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tahrif edilmiş payload ErrBadSignature dönmeli: %v", err)
	}

	// 4) Yanlış tenant → DENY.
	if err := v.Verify(mkSigned("agent-1", "globex", 3, now, "n3", payload, priv)); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("yanlış tenant ErrTenantMismatch dönmeli: %v", err)
	}

	// 5) Sequence gerilemesi (seq <= son kabul=2) → DENY.
	if err := v.Verify(mkSigned("agent-1", "acme", 2, now, "n5", payload, priv)); !errors.Is(err, ErrSequenceRollback) {
		t.Fatalf("sequence gerilemesi ErrSequenceRollback dönmeli: %v", err)
	}

	// 6) Replay (nonce n1 daha önce görüldü) — seq ileri olsa bile → DENY.
	if err := v.Verify(mkSigned("agent-1", "acme", 3, now, "n1", payload, priv)); !errors.Is(err, ErrReplay) {
		t.Fatalf("tekrar kullanılan nonce ErrReplay dönmeli: %v", err)
	}

	// 7) Bayat timestamp (pencere dışı) → DENY.
	stale := now.Add(-2 * time.Minute)
	if err := v.Verify(mkSigned("agent-1", "acme", 3, stale, "n7", payload, priv)); !errors.Is(err, ErrExpiredTimestamp) {
		t.Fatalf("bayat timestamp ErrExpiredTimestamp dönmeli: %v", err)
	}

	// 8) Bilinmeyen agent → DENY.
	if err := v.Verify(mkSigned("agent-X", "acme", 1, now, "n8", payload, priv)); !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("bilinmeyen agent ErrUnknownAgent dönmeli: %v", err)
	}
}

// TestTrustVerifierRejectStateNotPolluted, imzası geçersiz bir isteğin anti-replay
// durumunu KİRLETMEDİĞİNİ doğrular (durum yalnız imza doğrulandıktan sonra güncellenir).
func TestTrustVerifierRejectStateNotPolluted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // farklı anahtar
	reg := NewMemKeyRegistry()
	reg.Register("a", pub, "t")
	now := time.Now()
	v := NewTrustVerifier(reg, func() time.Time { return now }, time.Minute)

	// Yanlış anahtarla imzalanmış (seq=5, nonce=z) → DENY, durumu kirletmemeli.
	forged := SignedObservation{AgentID: "a", TenantID: "t", Sequence: 5, Timestamp: now, Nonce: "z", Payload: []byte("p")}
	forged.Signature = ed25519.Sign(other, SigningBytes(forged))
	if err := v.Verify(forged); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("sahte imza ErrBadSignature dönmeli: %v", err)
	}
	// Şimdi aynı seq/nonce ile GEÇERLİ imza → KABUL (önceki ret durumu bozmadı).
	if err := v.Verify(mkSigned("a", "t", 5, now, "z", []byte("p"), priv)); err != nil {
		t.Fatalf("geçerli telemetri kabul edilmeli (ret durumu kirletmemeliydi): %v", err)
	}
}

// TestTrustVerifierNoncePerAgentNamespace, nonce ad-alanının AGENT BAŞINA olduğunu
// doğrular: iki farklı ajan AYNI nonce dizesini kullanabilir (biri diğerini reddedemez),
// ama aynı ajan kendi nonce'unu yeniden kullanamaz (replay). (Denetim düzeltmesi: nonce
// eskiden global namespace'ti → ajanlar-arası çakışma meşru telemetriyi reddedebiliyordu.)
func TestTrustVerifierNoncePerAgentNamespace(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	reg := NewMemKeyRegistry()
	reg.Register("agent-A", pubA, "t1")
	reg.Register("agent-B", pubB, "t1")
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	v := NewTrustVerifier(reg, func() time.Time { return now }, time.Minute)
	p := []byte(`{"nodes":[]}`)

	// Agent A, "shared" nonce'uyla → KABUL.
	if err := v.Verify(mkSigned("agent-A", "t1", 1, now, "shared", p, privA)); err != nil {
		t.Fatalf("agent-A ilk gözlem kabul edilmeli: %v", err)
	}
	// Agent B, AYNI "shared" nonce'uyla → KABUL (ad-alanı agent başına; çakışma yok).
	if err := v.Verify(mkSigned("agent-B", "t1", 1, now, "shared", p, privB)); err != nil {
		t.Fatalf("agent-B aynı nonce'u kullanabilmeli (per-agent namespace): %v", err)
	}
	// Agent A kendi "shared" nonce'unu tekrar kullanırsa → REPLAY.
	if err := v.Verify(mkSigned("agent-A", "t1", 2, now, "shared", p, privA)); !errors.Is(err, ErrReplay) {
		t.Fatalf("agent-A kendi nonce'unu yeniden kullanınca ErrReplay dönmeli: %v", err)
	}
}
