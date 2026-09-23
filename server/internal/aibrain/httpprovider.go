package aibrain

// httpprovider.go — opsiyonel DIŞ AI servisine (LLM/ML mikroservisi) HTTP/JSON köprüsü.
// Provider'ı gerçekler; TÜM metotlar FAIL-OPEN'dır (hata/timeout/non-2xx → err) — Brain
// bunu yutup deterministik yola döner. Ham veri sızdırılmaz: yalnız türetilmiş girdiler
// (özet metinleri, sinyaller, graf ÖZELLİKLERİ — ham graf değil, §5.4) gönderilir.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kut.corp/suite/server/internal/riskfusion"
)

// HTTPProvider, dış AI servisini soyutlayan Provider gerçekleştirimidir.
type HTTPProvider struct {
	base   string
	key    string
	model  string
	client *http.Client
}

// NewHTTPProvider oluşturur. baseURL zorunlu; apiKey opsiyonel (Bearer). timeout<=0 → 5s.
func NewHTTPProvider(baseURL, apiKey, model string, timeout time.Duration) *HTTPProvider {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPProvider{
		base:   strings.TrimRight(baseURL, "/"),
		key:    apiKey,
		model:  model,
		client: &http.Client{Timeout: timeout},
	}
}

// postJSON, req'i {base}{path}'e POST eder ve yanıtı out'a çözer. non-2xx/hata → err.
func (h *HTTPProvider) postJSON(ctx context.Context, path string, reqBody, out any) error {
	b, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.key != "" {
		req.Header.Set("Authorization", "Bearer "+h.key)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("aibrain http: durum %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// src, yanıtın kaynağını denetlenebilir kılar: servis belirtmediyse "llm:<model>".
func (h *HTTPProvider) src(s string) string {
	if strings.TrimSpace(s) != "" {
		return s
	}
	if h.model != "" {
		return "llm:" + h.model
	}
	return "llm"
}

func (h *HTTPProvider) SummarizeIncident(ctx context.Context, in IncidentInput) (Summary, error) {
	var r struct {
		Text       string  `json:"text"`
		Confidence float64 `json:"confidence"`
		Source     string  `json:"source"`
	}
	if err := h.postJSON(ctx, "/v1/summarize", in, &r); err != nil {
		return Summary{}, err
	}
	return Summary{Text: r.Text, Confidence: r.Confidence, Source: h.src(r.Source)}, nil
}

func (h *HTTPProvider) SuggestTriage(ctx context.Context, in TriageInput) (Triage, error) {
	var r struct {
		Priority   string   `json:"priority"`
		LikelyFP   bool     `json:"likely_fp"`
		NextSteps  []string `json:"next_steps"`
		Confidence float64  `json:"confidence"`
		Source     string   `json:"source"`
	}
	if err := h.postJSON(ctx, "/v1/triage", in, &r); err != nil {
		return Triage{}, err
	}
	return Triage{Priority: r.Priority, LikelyFP: r.LikelyFP, NextSteps: r.NextSteps, Confidence: r.Confidence, Source: h.src(r.Source)}, nil
}

func (h *HTTPProvider) ScoreSequence(ctx context.Context, in SequenceInput) (SequenceScore, error) {
	var r struct {
		Score     float64 `json:"score"`
		Rationale string  `json:"rationale"`
		Source    string  `json:"source"`
	}
	if err := h.postJSON(ctx, "/v1/score-sequence", in, &r); err != nil {
		return SequenceScore{}, err
	}
	return SequenceScore{Score: r.Score, Rationale: r.Rationale, Source: h.src(r.Source)}, nil
}

func (h *HTTPProvider) ScoreGraph(ctx context.Context, in GraphInput) (GraphScore, error) {
	// Ham graf DEĞİL, yalnız türetilmiş özellikler + odak kimliği gönderilir (§5.4).
	body := map[string]any{
		"focus_kind": string(in.Focus.Kind), "focus_id": in.Focus.ID,
		"max_depth": in.MaxDepth, "features": in.Features,
	}
	var r struct {
		Score     float64 `json:"score"`
		Rationale string  `json:"rationale"`
		Source    string  `json:"source"`
	}
	if err := h.postJSON(ctx, "/v1/score-graph", body, &r); err != nil {
		return GraphScore{}, err
	}
	return GraphScore{Score: r.Score, Rationale: r.Rationale, Source: h.src(r.Source)}, nil
}

func (h *HTTPProvider) ExplainRisk(ctx context.Context, res riskfusion.Result) (Explanation, error) {
	var r struct {
		Text   string `json:"text"`
		Source string `json:"source"`
	}
	if err := h.postJSON(ctx, "/v1/explain-risk", res, &r); err != nil {
		return Explanation{}, err
	}
	return Explanation{Text: r.Text, Source: h.src(r.Source)}, nil
}

// Health, dış servisin sağlığını yoklar (GET {base}/health; 2xx = sağlıklı).
func (h *HTTPProvider) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+"/health", nil)
	if err != nil {
		return err
	}
	if h.key != "" {
		req.Header.Set("Authorization", "Bearer "+h.key)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("aibrain http: sağlıksız (durum %d)", resp.StatusCode)
	}
	return nil
}
