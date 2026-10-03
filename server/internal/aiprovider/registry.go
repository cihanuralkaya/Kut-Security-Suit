package aiprovider

import (
	"errors"
	"sort"
	"strings"
	"sync"
)

// ModelCapability defines what tasks a model is good at.
type ModelCapability string

const (
	CapabilityTriage          ModelCapability = "triage"
	CapabilityHunting         ModelCapability = "hunting"
	CapabilityInvestigation   ModelCapability = "investigation"
	CapabilityCodeAnalysis    ModelCapability = "code_analysis"
	CapabilityOfflineFallback ModelCapability = "offline_fallback"
)

// ModelMetadata represents the configuration and state of an AI model.
type ModelMetadata struct {
	ID           string
	ProviderName string
	Capabilities []ModelCapability
	IsLocal      bool
	MaxTokens    int
	LatencyMs    int64
	Healthy      bool
}

// ModelRegistry manages the availability and selection of AI models.
type ModelRegistry struct {
	mu     sync.RWMutex
	models map[string]*ModelMetadata
}

// NewModelRegistry creates a new empty ModelRegistry.
func NewModelRegistry() *ModelRegistry {
	return &ModelRegistry{
		models: make(map[string]*ModelMetadata),
	}
}

// RegisterModel adds a new model to the registry.
// Modele ait metadata bilgilerini kayıt altına alır.
func (r *ModelRegistry) RegisterModel(meta ModelMetadata) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if meta.ID == "" {
		return errors.New("model ID cannot be empty")
	}

	if _, exists := r.models[meta.ID]; exists {
		return errors.New("model already registered")
	}

	r.models[meta.ID] = &meta
	return nil
}

// SelectBestModel chooses the most suitable model based on capability and health.
// PreferLocal forces the selection of a local model if one exists for the capability.
// Sağlıklı modeller arasından kapasiteye uyan ve en düşük gecikmeye sahip modeli seçer.
func (r *ModelRegistry) SelectBestModel(capability ModelCapability, preferLocal bool) (*ModelMetadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var candidates []*ModelMetadata

	for _, m := range r.models {
		if !m.Healthy {
			continue
		}

		hasCapability := false
		for _, cap := range m.Capabilities {
			if cap == capability {
				hasCapability = true
				break
			}
		}

		if hasCapability {
			if preferLocal && !m.IsLocal {
				continue
			}
			candidates = append(candidates, m)
		}
	}

	// Eğer aday bulunamadıysa (preferLocal sebebiyle veya tüm dış modeller çevrimdışıysa)
	// Offline fallback modellerine yöneliriz.
	if len(candidates) == 0 {
		for _, m := range r.models {
			if m.Healthy {
				if preferLocal && !m.IsLocal {
					continue
				}
				for _, cap := range m.Capabilities {
					if cap == CapabilityOfflineFallback {
						return m, nil
					}
				}
			}
		}

		return nil, errors.New("no healthy models available for the requested capability")
	}

	// En düşük gecikme süresine göre sırala (Sort candidates by LatencyMs)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].LatencyMs < candidates[j].LatencyMs
	})

	return candidates[0], nil
}

// UpdateHealth modifies the health status and latency of an existing model.
// Modelin anlık sağlık durumunu ve gecikmesini günceller.
func (r *ModelRegistry) UpdateHealth(modelID string, healthy bool, latencyMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	m, exists := r.models[modelID]
	if !exists {
		return errors.New("model not found")
	}

	m.Healthy = healthy
	m.LatencyMs = latencyMs
	return nil
}

// LocalHeuristicClassifier implements offline deterministic security classification.
// This is used as a fallback when AI providers are unavailable.
type LocalHeuristicClassifier struct{}

// Classify performs a basic pattern scoring on input text to determine threat level.
// Çevrimdışı durumlarda temel desen eşleştirme ile hızlı tehdit analizi yapar.
func (l *LocalHeuristicClassifier) Classify(input string) string {
	inputLower := strings.ToLower(input)
	score := 0

	// Basit sezgisel kurallar (Simple heuristic rules)
	if strings.Contains(inputLower, "exec(") || strings.Contains(inputLower, "system(") {
		score += 50
	}
	if strings.Contains(inputLower, "base64_decode") {
		score += 30
	}
	if strings.Contains(inputLower, "/etc/passwd") || strings.Contains(inputLower, "cmd.exe") {
		score += 40
	}
	if strings.Contains(inputLower, "select * from") && strings.Contains(inputLower, "where") {
		score += 20 // Potansiyel SQLi
	}

	if score >= 50 {
		return "HIGH_THREAT"
	} else if score >= 20 {
		return "MEDIUM_THREAT"
	}
	return "LOW_THREAT"
}
