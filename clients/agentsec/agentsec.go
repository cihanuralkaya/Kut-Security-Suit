// Package agentsec, KUT Agentic Threat Defense telemetri ucuna (POST /api/agentsec/events)
// agent-davranış gözlemleri gönderen HAFİF bir Go client'ıdır (yalnız stdlib; server
// iç paketlerine bağımsız — dış AI-agent runtime'ları güvenle import edebilir).
//
// Bir agent-runtime, gözlemlerini (düğüm + kenar) bir Batch'te toplayıp Report ile
// gönderir; KUT bunları Agent Causality Graph'a örer ve exfil zincirlerini
// (untrusted → credential → external) tespit eder. Gözlemler DATA'dır; hiçbir yürütme
// tetiklemez (KUT enforcement'ı ActionRequest → Gateway → Grant → GuardedExecutor'dan geçer).
package agentsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Düğüm türleri (KUT sözleşmesiyle birebir).
const (
	KindAgent      = "agent"
	KindTool       = "tool"
	KindMemory     = "memory"
	KindContext    = "context"
	KindCredential = "credential"
	KindExternal   = "external"
)

// Güven düzeyleri. Bilinmeyen/boş sunucuda fail-safe Untrusted'a düşer (asla Trusted).
const (
	TrustTrusted   = "TRUSTED"
	TrustUntrusted = "UNTRUSTED"
	TrustTainted   = "TAINTED"
)

type node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Trust string `json:"trust"`
}

type edge struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Batch, tek istekte gönderilecek gözlemleri biriktirir. Zincirlenebilir (akıcı) API.
type Batch struct {
	nodes []node
	edges []edge
}

// NewBatch, boş bir gözlem yığını oluşturur.
func NewBatch() *Batch { return &Batch{} }

// Node, bir varlık gözlemi ekler (agent/tool/memory/context/credential/external + güven).
func (b *Batch) Node(id, kind, trust string) *Batch {
	b.nodes = append(b.nodes, node{ID: id, Kind: kind, Trust: trust})
	return b
}

// Read, "agent, source'u okudu" gözlemi (taint source → agent).
func (b *Batch) Read(agent, source string) *Batch {
	b.edges = append(b.edges, edge{Type: "read", From: agent, To: source})
	return b
}

// Write, "agent, sink'e yazdı" gözlemi (egress; exfil tespiti).
func (b *Batch) Write(agent, sink string) *Batch {
	b.edges = append(b.edges, edge{Type: "write", From: agent, To: sink})
	return b
}

// Delegate, "delegator → delegatee" delegation gözlemi.
func (b *Batch) Delegate(from, to string) *Batch {
	b.edges = append(b.edges, edge{Type: "delegate", From: from, To: to})
	return b
}

// Influence, "from → to" etki gözlemi.
func (b *Batch) Influence(from, to string) *Batch {
	b.edges = append(b.edges, edge{Type: "influence", From: from, To: to})
	return b
}

// Empty, yığının boş olup olmadığını döner (boş gönderim çağrılmasın diye).
func (b *Batch) Empty() bool { return len(b.nodes) == 0 && len(b.edges) == 0 }

// Client, KUT admin API'sine telemetri gönderen HTTP client'ıdır.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New, bir client oluşturur. baseURL KUT admin API kökü (ör. https://kut-c2:8445);
// token bir admin/entegrasyon bearer token'ı; timeout<=0 → 10s.
func New(baseURL, token string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		http:  &http.Client{Timeout: timeout},
	}
}

// Report, yığındaki gözlemleri POST /api/agentsec/events ile gönderir. Boş yığın no-op'tur.
// non-2xx / ağ hatası → error (çağıran yeniden dener; KUT tarafı fail-open, veri kaybı
// güvenlik-kritik değildir).
func (c *Client) Report(ctx context.Context, b *Batch) error {
	if b == nil || b.Empty() {
		return nil
	}
	payload := map[string]any{"nodes": b.nodes, "edges": b.edges}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/agentsec/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("agentsec: gönderim reddedildi (durum %d)", resp.StatusCode)
	}
	return nil
}
