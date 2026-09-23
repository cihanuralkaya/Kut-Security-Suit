package agentsec

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// wireWithSig, sunucunun /api/agentsec/telemetry'de çözdüğü kablo biçimidir.
type wireWithSig struct {
	AgentID   string    `json:"agent_id"`
	TenantID  string    `json:"tenant_id"`
	Sequence  uint64    `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     string    `json:"nonce"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"signature"`
}

// verifyLikeServer, ALINAN wire'dan kanonik baytları yeniden kurup imzayı doğrular —
// sunucu tarafının yaptığının aynısı. Böylece wire round-trip'i (payload base64, timestamp
// nanosaniye) ve imza doğruluğu birlikte kanıtlanır.
func verifyLikeServer(pub ed25519.PublicKey, w wireWithSig) bool {
	var b []byte
	add := func(s string) { b = append(b, s...); b = append(b, 0x1f) }
	add(w.AgentID)
	add(w.TenantID)
	add(strconv.FormatUint(w.Sequence, 10))
	add(strconv.FormatInt(w.Timestamp.UnixNano(), 10))
	add(w.Nonce)
	b = append(b, w.Payload...)
	return ed25519.Verify(pub, b, w.Signature)
}

func TestReportSignedProducesVerifiableWire(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var mu sync.Mutex
	var seqs []uint64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got wireWithSig
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		if got.AgentID != "agent-1" || got.TenantID != "t1" || got.Nonce == "" {
			http.Error(w, "alanlar", http.StatusBadRequest)
			return
		}
		if !verifyLikeServer(pub, got) {
			http.Error(w, "imza", http.StatusForbidden)
			return
		}
		mu.Lock()
		seqs = append(seqs, got.Sequence)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := New(ts.URL, "", time.Second)
	s := NewSigner("agent-1", "t1", priv)
	b := NewBatch().Node("a", KindAgent, TrustTrusted).Read("a", "web")

	// İki gönderim → imza doğrulanır (mock 200) ve sequence monoton artar.
	if err := c.ReportSigned(context.Background(), s, b); err != nil {
		t.Fatalf("1. imzalı gönderim geçmeli: %v", err)
	}
	if err := c.ReportSigned(context.Background(), s, b); err != nil {
		t.Fatalf("2. imzalı gönderim geçmeli: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 2 {
		t.Fatalf("sequence 1,2 monoton olmalı: %v", seqs)
	}
}

func TestReportSignedEmptyNoop(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := New(ts.URL, "", time.Second)
	if err := c.ReportSigned(context.Background(), NewSigner("a", "t", priv), NewBatch()); err != nil {
		t.Fatalf("boş yığın no-op: %v", err)
	}
	if called {
		t.Fatal("boş yığın istek göndermemeli")
	}
}
