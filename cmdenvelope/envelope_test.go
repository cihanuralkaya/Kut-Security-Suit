package cmdenvelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCanonicalBytes_Deterministic(t *testing.T) {
	a := CanonicalBytes("id1", "dev1", "WIPE", "adm1", map[string]any{"path": "x", "n": 3}, "nonce1", 100, 200)
	b := CanonicalBytes("id1", "dev1", "WIPE", "adm1", map[string]any{"n": 3, "path": "x"}, "nonce1", 100, 200)
	if !bytes.Equal(a, b) {
		t.Fatal("kanonik baytlar parametre harita sırasından bağımsız olmalı (sıralı hash)")
	}
}

func TestCanonicalBytes_FieldSensitivity(t *testing.T) {
	base := CanonicalBytes("id1", "dev1", "WIPE", "adm1", nil, "n1", 100, 200)
	// Her alan değişimi farklı bayt üretmeli (hiçbiri çakışmamalı).
	variants := [][]byte{
		CanonicalBytes("id2", "dev1", "WIPE", "adm1", nil, "n1", 100, 200),
		CanonicalBytes("id1", "dev2", "WIPE", "adm1", nil, "n1", 100, 200),
		CanonicalBytes("id1", "dev1", "LOCK", "adm1", nil, "n1", 100, 200),
		CanonicalBytes("id1", "dev1", "WIPE", "adm2", nil, "n1", 100, 200),
		CanonicalBytes("id1", "dev1", "WIPE", "adm1", map[string]any{"k": "v"}, "n1", 100, 200),
		CanonicalBytes("id1", "dev1", "WIPE", "adm1", nil, "n2", 100, 200),
		CanonicalBytes("id1", "dev1", "WIPE", "adm1", nil, "n1", 101, 200),
		CanonicalBytes("id1", "dev1", "WIPE", "adm1", nil, "n1", 100, 201),
	}
	for i, v := range variants {
		if bytes.Equal(base, v) {
			t.Errorf("varyant %d base ile çakıştı — alan ayrımı zayıf", i)
		}
	}
}

func TestVerifySignature_RoundTripAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canon := CanonicalBytes("id1", "dev1", "WIPE", "adm1", map[string]any{"path": "x"}, "n1", 100, 200)
	sig := ed25519.Sign(priv, canon)

	if !VerifySignature(pub, canon, sig) {
		t.Fatal("geçerli imza doğrulanmalı")
	}
	// Baytlar değişirse (ör. farklı cihaz) imza geçersiz.
	other := CanonicalBytes("id1", "dev2", "WIPE", "adm1", map[string]any{"path": "x"}, "n1", 100, 200)
	if VerifySignature(pub, other, sig) {
		t.Fatal("değiştirilmiş baytlar imzayı geçersiz kılmalı (çapraz-cihaz replay engeli)")
	}
	// Yanlış anahtar boyutu → fail-closed false.
	if VerifySignature(ed25519.PublicKey{1, 2, 3}, canon, sig) {
		t.Fatal("geçersiz anahtar boyutu false dönmeli")
	}
}
