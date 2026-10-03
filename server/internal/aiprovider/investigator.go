package aiprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"kut.corp/suite/server/internal/entitygraph"
)

// InvestigationReport represents the structured output of an investigation.
type InvestigationReport struct {
	IncidentID              string   `json:"incident_id"`
	Severity                string   `json:"severity"`
	Summary                 string   `json:"summary"`
	RootCause               string   `json:"root_cause"`
	MITRETechniques         []string `json:"mitre_techniques"`
	AttackPath              []string `json:"attack_path"`
	ChokePoints             []string `json:"choke_points"`
	RecommendedRemediations []string `json:"recommended_remediations"`
	Confidence              float64  `json:"confidence"`
}

// InvestigationAgent handles automated triage and investigation of incidents.
type InvestigationAgent struct {
	router *ModelRouter
	rag    *RAGStore
	dlp    *DataDLP
}

// NewInvestigationAgent creates a new InvestigationAgent.
func NewInvestigationAgent(router *ModelRouter, rag *RAGStore, dlp *DataDLP) *InvestigationAgent {
	return &InvestigationAgent{
		router: router,
		rag:    rag,
		dlp:    dlp,
	}
}

// Investigate analyzes an incident and produces a structured report.
func (a *InvestigationAgent) Investigate(ctx context.Context, incidentID string, category string, message string, attackPaths []entitygraph.Path, chokePoints []entitygraph.ChokePoint) (InvestigationReport, error) {
	// 1. Apply DLP redaction to the incident message
	rmap := NewRedactionMap()
	redactedMessage := a.dlp.MapRedactions(message, rmap)

	// 2. Retrieve context from RAG store based on category and message
	query := fmt.Sprintf("%s %s", category, redactedMessage)
	
	// We'll use SearchKeyword as a simple search for knowledge
	topDocs := a.rag.SearchKeyword(query, 3)
	
	var ragContextStr strings.Builder
	for i, r := range topDocs {
		if i > 0 {
			ragContextStr.WriteString("\n")
		}
		ragContextStr.WriteString(fmt.Sprintf("%s: %s", r.Doc.Title, r.Doc.Content))
	}

	// 3. Format prompt with context, paths, and choke points
	prompt := fmt.Sprintf(`You are an autonomous security investigation agent.
Analyze the following security incident and provide a structured JSON report.
Incident ID: %s
Category: %s
Message: %s

Knowledge Context:
%s

Attack Paths:
%+v

Choke Points:
%+v

Output JSON matching the following schema:
{
  "incident_id": "string",
  "severity": "string",
  "summary": "string",
  "root_cause": "string",
  "mitre_techniques": ["string"],
  "attack_path": ["string"],
  "choke_points": ["string"],
  "recommended_remediations": ["string"],
  "confidence": 0.0
}`, incidentID, category, redactedMessage, ragContextStr.String(), attackPaths, chokePoints)

	// 4. Generate analysis via ModelRouter
	req := CompletionRequest{
		Messages: []ChatMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
		Sensitivity: Restricted,
	}
	resp, err := a.router.RouteComplete(ctx, req)
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("model generation failed: %w", err)
	}
	responseStr := resp.Content

	// Remove any potential markdown code blocks (```json ... ```)
	responseStr = strings.TrimPrefix(responseStr, "```json\n")
	responseStr = strings.TrimPrefix(responseStr, "```\n")
	responseStr = strings.TrimSuffix(responseStr, "\n```")
	responseStr = strings.TrimSuffix(responseStr, "```")

	// 5. Parse output into InvestigationReport
	var report InvestigationReport
	if err := json.Unmarshal([]byte(responseStr), &report); err != nil {
		return InvestigationReport{}, fmt.Errorf("failed to parse model output: %w\nOutput: %s", err, responseStr)
	}

	// 6. Rehydrate the summary with DLP vault
	report.Summary = a.dlp.Rehydrate(report.Summary, rmap)
	report.RootCause = a.dlp.Rehydrate(report.RootCause, rmap)

	return report, nil
}
