package aiprovider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalInvestigationProvider_EmitsValidReport(t *testing.T) {
	p := NewLocalInvestigationProvider()
	prompt := "You are an autonomous security investigation agent.\n" +
		"Incident ID: inc-42\n" +
		"Category: SECURITY\n" +
		"Message: ransom note dropped, vssadmin delete shadows /all /quiet\n\n" +
		"Knowledge Context:\n(none)\n"
	resp, err := p.Complete(context.Background(), CompletionRequest{
		Messages: []ChatMessage{{Role: "user", Content: prompt}}, Sensitivity: Restricted,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var rep InvestigationReport
	if err := json.Unmarshal([]byte(resp.Content), &rep); err != nil {
		t.Fatalf("yerel sağlayıcı geçerli InvestigationReport JSON üretmeli: %v\nout=%s", err, resp.Content)
	}
	if rep.IncidentID != "inc-42" {
		t.Errorf("incident_id inc-42 bekleniyordu, alındı %q", rep.IncidentID)
	}
	if rep.Severity != "CRITICAL" {
		t.Errorf("fidye → CRITICAL bekleniyordu, alındı %q", rep.Severity)
	}
	if !contains(rep.MITRETechniques, "T1486") {
		t.Errorf("fidye → T1486 teknik bekleniyordu, alındı %v", rep.MITRETechniques)
	}
	if len(rep.RecommendedRemediations) == 0 {
		t.Error("en az bir remediation önerisi bekleniyordu")
	}
}

// TestInvestigationAgent_EndToEndWithLocalProvider, tüm Investigator hattının (DLP
// redaksiyon → RAG → prompt → yerel sağlayıcı → parse → rehydrate) SIFIR-AĞ uçtan uca
// çalıştığını doğrular — agentic mesh'in canlı-erişilebilirlik kanıtı.
func TestInvestigationAgent_EndToEndWithLocalProvider(t *testing.T) {
	router := NewModelRouter(NewLocalInvestigationProvider(), nil, NewMockProvider())
	agent := NewInvestigationAgent(router, NewRAGStore(), NewDataDLP())
	rep, err := agent.Investigate(context.Background(), "inc-7", "SECURITY",
		"certutil -decode payload.b64 payload.exe; anydesk.exe --install", nil, nil)
	if err != nil {
		t.Fatalf("uçtan uca soruşturma başarısız: %v", err)
	}
	if rep.IncidentID != "inc-7" {
		t.Errorf("incident_id inc-7 bekleniyordu, alındı %q", rep.IncidentID)
	}
	if !contains(rep.MITRETechniques, "T1140") || !contains(rep.MITRETechniques, "T1219") {
		t.Errorf("certutil→T1140 + anydesk→T1219 bekleniyordu, alındı %v", rep.MITRETechniques)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
