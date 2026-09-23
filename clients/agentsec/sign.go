package agentsec

// sign.go — P0-A: imzalı telemetri. Bir agent, gözlemlerini ed25519 ile imzalayıp
// KUT'un imza-doğrulamalı ucuna (POST /api/agentsec/telemetry) gönderir. Sunucu
// (server/internal/aisec.TrustVerifier) imzayı + tenant + sequence + anti-replay +
// tazeliği doğrular. signingBytes layout'u aisec.SigningBytes ile BİREBİR AYNI olmalıdır.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Signer, bir agent'ın kimliği + ed25519 özel anahtarı + monoton sequence sayacıdır.
type Signer struct {
	AgentID  string
	TenantID string
	priv     ed25519.PrivateKey

	mu  sync.Mutex
	seq uint64
}

// NewSigner oluşturur. priv, agent'ın ed25519 özel anahtarıdır; karşılık gelen açık
// anahtar sunucuda KUT_AGENT_KEYS ile agentID+tenant'a kayıtlı olmalıdır.
func NewSigner(agentID, tenantID string, priv ed25519.PrivateKey) *Signer {
	return &Signer{AgentID: agentID, TenantID: tenantID, priv: priv}
}

func (s *Signer) next() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.seq
}

// signingBytes, imzalanacak KANONİK baytları üretir. server/internal/aisec.SigningBytes
// ile AYNI olmalı (alan sırası + 0x1f ayraç + payload sonda). Değişirse iki taraf da
// güncellenmeli, yoksa imza doğrulaması kırılır.
func signingBytes(agentID, tenantID string, seq uint64, ts time.Time, nonce string, payload []byte) []byte {
	var b []byte
	add := func(s string) { b = append(b, s...); b = append(b, 0x1f) }
	add(agentID)
	add(tenantID)
	add(strconv.FormatUint(seq, 10))
	add(strconv.FormatInt(ts.UnixNano(), 10))
	add(nonce)
	b = append(b, payload...)
	return b
}

func randNonce() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "n_fallback"
	}
	return hex.EncodeToString(b[:])
}

// ReportSigned, yığındaki gözlemleri İMZALAYIP /api/agentsec/telemetry'ye gönderir. Her
// çağrı monoton artan bir sequence + taze nonce + timestamp kullanır (anti-replay). Boş
// yığın no-op; non-2xx (ör. 403 imza reddi) → error.
func (c *Client) ReportSigned(ctx context.Context, s *Signer, b *Batch) error {
	if b == nil || b.Empty() {
		return nil
	}
	payload, err := json.Marshal(map[string]any{"nodes": b.nodes, "edges": b.edges})
	if err != nil {
		return err
	}
	ts := time.Now()
	nonce := randNonce()
	seq := s.next()
	sig := ed25519.Sign(s.priv, signingBytes(s.AgentID, s.TenantID, seq, ts, nonce, payload))

	wire := map[string]any{
		"agent_id":  s.AgentID,
		"tenant_id": s.TenantID,
		"sequence":  seq,
		"timestamp": ts,
		"nonce":     nonce,
		"payload":   payload, // json → base64
		"signature": sig,     // json → base64
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/agentsec/telemetry", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("agentsec: imzalı telemetri reddedildi (durum %d)", resp.StatusCode)
	}
	return nil
}
