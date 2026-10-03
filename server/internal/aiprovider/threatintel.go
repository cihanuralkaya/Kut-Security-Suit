package aiprovider

import (
	"sync"
	"time"
)

// IOCType defines the type of Indicator of Compromise.
type IOCType string

const (
	IOCTypeIPv4   IOCType = "ipv4"
	IOCTypeDomain IOCType = "domain"
	IOCTypeSHA256 IOCType = "sha256"
	IOCTypeURL    IOCType = "url"
)

// ThreatIndicator represents a single piece of threat intelligence.
type ThreatIndicator struct {
	Value           string
	Type            IOCType
	ThreatActor     string
	MalwareFamily   string
	ConfidenceScore float64
	FirstSeen       time.Time
	LastSeen        time.Time
	Tags            []string
}

// EnrichmentResult contains the intelligence gathered for a specific indicator.
type EnrichmentResult struct {
	Indicator        string
	IsKnownMalicious bool
	ReputationScore  float64 // 0.0 to 1.0 (1.0 meaning highly malicious)
	MatchedActors    []string
	MatchedFamilies  []string
}

// ThreatIntelAgent provides IOC enrichment and threat intelligence storage.
type ThreatIntelAgent struct {
	mu         sync.RWMutex
	indicators map[string]ThreatIndicator // key: indicator value
}

// NewThreatIntelAgent creates a new instance of ThreatIntelAgent.
func NewThreatIntelAgent() *ThreatIntelAgent {
	return &ThreatIntelAgent{
		indicators: make(map[string]ThreatIndicator),
	}
}

// IngestIndicator adds a new threat indicator to the in-memory store.
func (a *ThreatIntelAgent) IngestIndicator(indicator ThreatIndicator) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.indicators[indicator.Value] = indicator
	return nil
}

// EnrichIOC checks the store for the given IOC and returns an EnrichmentResult.
func (a *ThreatIntelAgent) EnrichIOC(ioc string, iocType IOCType) EnrichmentResult {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := EnrichmentResult{
		Indicator:       ioc,
		MatchedActors:   []string{},
		MatchedFamilies: []string{},
	}

	indicator, exists := a.indicators[ioc]
	if !exists {
		return result
	}

	if indicator.ConfidenceScore >= 0.7 {
		result.IsKnownMalicious = true
	}
	result.ReputationScore = indicator.ConfidenceScore

	if indicator.ThreatActor != "" {
		result.MatchedActors = append(result.MatchedActors, indicator.ThreatActor)
	}
	if indicator.MalwareFamily != "" {
		result.MatchedFamilies = append(result.MatchedFamilies, indicator.MalwareFamily)
	}

	return result
}

// BulkEnrich enriches multiple IOCs at once.
func (a *ThreatIntelAgent) BulkEnrich(iocs []string) []EnrichmentResult {
	var results []EnrichmentResult
	for _, ioc := range iocs {
		results = append(results, a.EnrichIOC(ioc, ""))
	}
	return results
}
