package aiprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMockProvider(t *testing.T) {
	provider := NewMockProvider()
	resp, err := provider.Complete(context.Background(), CompletionRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "mock response" {
		t.Errorf("expected 'mock response', got '%s'", resp.Content)
	}
}

func TestOpenAICompatProvider(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			resp := openAIResp{}
			resp.Choices = append(resp.Choices, struct {
				Message ChatMessage `json:"message"`
			}{
				Message: ChatMessage{Role: "assistant", Content: "hello"},
			})
			resp.Usage.TotalTokens = 10
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	provider := NewOpenAICompatProvider(ts.URL, "test-key", "test-model", time.Second)
	resp, err := provider.Complete(context.Background(), CompletionRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "hello" {
		t.Errorf("expected 'hello', got '%s'", resp.Content)
	}
}

func TestDataDLP(t *testing.T) {
	dlp := NewDataDLP()
	rmap := NewRedactionMap()
	
	original := "Contact me at test@example.com or IP 192.168.1.1."
	redacted := dlp.MapRedactions(original, rmap)
	
	if strings.Contains(redacted, "test@example.com") {
		t.Errorf("email not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "192.168.1.1") {
		t.Errorf("IP not redacted: %s", redacted)
	}
	
	rehydrated := dlp.Rehydrate(redacted, rmap)
	if rehydrated != original {
		t.Errorf("expected '%s', got '%s'", original, rehydrated)
	}
}

func TestModelRouter(t *testing.T) {
	mock := NewMockProvider()
	router := NewModelRouter(nil, nil, mock)
	
	req := CompletionRequest{Sensitivity: Restricted}
	_, err := router.RouteComplete(context.Background(), req)
	if err == nil || err.Error() != "restricted sensitivity requires local provider, but none is configured" {
		t.Errorf("expected error about local provider, got: %v", err)
	}
	
	routerWithLocal := NewModelRouter(mock, nil, nil)
	resp, err := routerWithLocal.RouteComplete(context.Background(), req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp.Content != "mock response" {
		t.Errorf("unexpected response: %s", resp.Content)
	}
}
