package aiprovider

import (
	"context"
	"fmt"

	"kut.corp/suite/server/internal/entitygraph"
)

// HuntHypothesis represents a threat hunting hypothesis.
type HuntHypothesis struct {
	ID             string
	Title          string
	MITRETactic    string
	MITRETechnique string
	Description    string
	TargetKind     entitygraph.Kind
}

// HuntFinding represents a finding from executing a hunt hypothesis.
type HuntFinding struct {
	HypothesisID    string
	TargetNode      entitygraph.Node
	SuspiciousEdges []entitygraph.Edge
	RiskScore       float64
	Summary         string
}

// HuntingAgent is an autonomous threat hunting agent.
type HuntingAgent struct {
	Graph       *entitygraph.Graph
	RAGStore    *RAGStore
	ModelRouter *ModelRouter
}

// GenerateHypotheses generates threat hunting hypotheses based on a focus tactic.
func (a *HuntingAgent) GenerateHypotheses(ctx context.Context, focusTactic string) ([]HuntHypothesis, error) {
	// A gerçek implementasyonda, model router ve RAG store kullanılarak
	// taktik odaklı hipotezler üretilecektir.
	if focusTactic == "" {
		return nil, fmt.Errorf("focusTactic belirtilmelidir")
	}

	return []HuntHypothesis{
		{
			ID:             "hyp-1",
			Title:          "Anomalous Process Execution",
			MITRETactic:    focusTactic,
			MITRETechnique: "T1059",
			Description:    "Hunt for processes executing unusual command lines.",
			TargetKind:     entitygraph.Kind("Process"),
		},
	}, nil
}

// ExecuteHunt traverses the entitygraph for anomalous relationships matching the hypothesis.
func (a *HuntingAgent) ExecuteHunt(ctx context.Context, h HuntHypothesis) ([]HuntFinding, error) {
	if a.Graph == nil {
		return nil, fmt.Errorf("graf bulunamadı")
	}

	var findings []HuntFinding
	nodes := a.Graph.NodesByKind(h.TargetKind)
	for _, node := range nodes {
		edges := a.Graph.OutEdges(node)
		if len(edges) > 0 {
			var suspicious []entitygraph.Edge
			for _, e := range edges {
				if e.Count <= 2 { // Rare or anomalous connection
					suspicious = append(suspicious, e)
				}
			}
			if len(suspicious) > 0 {
				findings = append(findings, HuntFinding{
					HypothesisID:    h.ID,
					TargetNode:      node,
					SuspiciousEdges: suspicious,
					RiskScore:       0.85,
					Summary:         fmt.Sprintf("Hipotez %s ile eşleşen %d nadir/şüpheli bağlantı bulundu", h.ID, len(suspicious)),
				})
			}
		}
	}

	return findings, nil
}
