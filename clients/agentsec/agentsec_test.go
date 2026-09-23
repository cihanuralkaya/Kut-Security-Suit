package agentsec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReportSendsContractPayload(t *testing.T) {
	var gotPath, gotAuth string
	var got struct {
		Nodes []map[string]string `json:"nodes"`
		Edges []map[string]string `json:"edges"`
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := New(ts.URL, "tok1", time.Second)
	b := NewBatch().
		Node("web", KindContext, TrustUntrusted).
		Node("agent", KindAgent, TrustTrusted).
		Node("cred", KindCredential, TrustTrusted).
		Node("evil", KindExternal, TrustTrusted).
		Read("agent", "web").Read("agent", "cred").Write("agent", "evil")

	if err := c.Report(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/agentsec/events" {
		t.Fatalf("yol /api/agentsec/events olmalı: %s", gotPath)
	}
	if gotAuth != "Bearer tok1" {
		t.Fatalf("bearer token gönderilmeli: %q", gotAuth)
	}
	if len(got.Nodes) != 4 || len(got.Edges) != 3 {
		t.Fatalf("4 düğüm + 3 kenar bekleniyordu: %+v", got)
	}
	// Kenar sözleşmesi: read/write + from/to alanları.
	if got.Edges[0]["type"] != "read" || got.Edges[0]["from"] != "agent" || got.Edges[0]["to"] != "web" {
		t.Fatalf("read kenarı hatalı: %+v", got.Edges[0])
	}
	if got.Edges[2]["type"] != "write" || got.Edges[2]["to"] != "evil" {
		t.Fatalf("write kenarı hatalı: %+v", got.Edges[2])
	}
	// Düğüm sözleşmesi: id/kind/trust.
	if got.Nodes[0]["kind"] != "context" || got.Nodes[0]["trust"] != "UNTRUSTED" {
		t.Fatalf("düğüm hatalı: %+v", got.Nodes[0])
	}
}

func TestReportEmptyIsNoop(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := New(ts.URL, "", time.Second)
	if err := c.Report(context.Background(), NewBatch()); err != nil {
		t.Fatalf("boş yığın no-op olmalı: %v", err)
	}
	if called {
		t.Fatal("boş yığın istek göndermemeli")
	}
}

func TestReportNon2xxError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "reddedildi", http.StatusForbidden)
	}))
	defer ts.Close()
	c := New(ts.URL, "", time.Second)
	err := c.Report(context.Background(), NewBatch().Node("a", KindAgent, TrustTainted))
	if err == nil {
		t.Fatal("non-2xx hata dönmeliydi")
	}
}

// ExampleClient_Report, bir agent-runtime'ın exfil-şüpheli bir zinciri nasıl bildireceğini
// gösterir.
func ExampleClient_Report() {
	c := New("https://kut-c2:8445", "integration-token", 0)
	b := NewBatch().
		Node("assistant", KindAgent, TrustTrusted).
		Node("web-scrape", KindContext, TrustUntrusted).
		Node("api-key", KindCredential, TrustTrusted).
		Node("paste.evil", KindExternal, TrustTrusted).
		Read("assistant", "web-scrape").
		Read("assistant", "api-key").
		Write("assistant", "paste.evil")
	_ = c.Report(context.Background(), b)
}
