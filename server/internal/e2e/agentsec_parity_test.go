package e2e

// agentsec_parity_test.go — P0-A parite garantisi: clients/agentsec SDK'sının ürettiği
// imza, sunucu tarafındaki server/internal/aisec.TrustVerifier tarafından KABUL edilmeli.
// SDK ve sunucu, imza için ayrı signingBytes gerçekleştirimlerine sahip (SDK aisec'i
// import edemez — internal); bu test ikisinin AYNI kanonik baytları ürettiğini uçtan uca
// (gerçek HTTP wire üzerinden) kanıtlar. Layout birinde değişip diğerinde değişmezse bu
// test kırılır.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kut.corp/suite/clients/agentsec"
	"kut.corp/suite/server/internal/aisec"
)

func TestAgentSecSDKSignatureParity(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	reg := aisec.NewMemKeyRegistry()
	reg.Register("agent-1", pub, "t1")
	v := aisec.NewTrustVerifier(reg, nil, time.Minute)

	var verifyErr error
	seen := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire struct {
			AgentID   string    `json:"agent_id"`
			TenantID  string    `json:"tenant_id"`
			Sequence  uint64    `json:"sequence"`
			Timestamp time.Time `json:"timestamp"`
			Nonce     string    `json:"nonce"`
			Payload   []byte    `json:"payload"`
			Signature []byte    `json:"signature"`
		}
		if e := json.NewDecoder(r.Body).Decode(&wire); e != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		seen = true
		// SUNUCU tarafının gerçek doğrulayıcısıyla doğrula (SDK'nın imzasını).
		verifyErr = v.Verify(aisec.SignedObservation{
			AgentID: wire.AgentID, TenantID: wire.TenantID, Sequence: wire.Sequence,
			Timestamp: wire.Timestamp, Nonce: wire.Nonce, Payload: wire.Payload, Signature: wire.Signature,
		})
		if verifyErr != nil {
			http.Error(w, verifyErr.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := agentsec.New(ts.URL, "", time.Second)
	s := agentsec.NewSigner("agent-1", "t1", priv)
	b := agentsec.NewBatch().
		Node("agent", agentsec.KindAgent, agentsec.TrustTrusted).
		Node("web", agentsec.KindContext, agentsec.TrustUntrusted).
		Read("agent", "web")

	if err := c.ReportSigned(context.Background(), s, b); err != nil {
		t.Fatalf("SDK-imzalı telemetri aisec.TrustVerifier'dan geçmeli (parite): %v (verify=%v)", err, verifyErr)
	}
	if !seen {
		t.Fatal("sunucu isteği almadı")
	}
	if verifyErr != nil {
		t.Fatalf("parite bozuk — SDK imzası aisec ile doğrulanamadı: %v", verifyErr)
	}
}
