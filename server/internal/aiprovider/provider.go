package aiprovider

import "context"

type Sensitivity int

const (
	Public Sensitivity = iota
	Internal
	Confidential
	Restricted
)

func (s Sensitivity) String() string {
	switch s {
	case Public:
		return "Public"
	case Internal:
		return "Internal"
	case Confidential:
		return "Confidential"
	case Restricted:
		return "Restricted"
	default:
		return "Unknown"
	}
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type CompletionRequest struct {
	Messages    []ChatMessage `json:"messages"`
	Temperature float32       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Sensitivity Sensitivity   `json:"-"` // Internal use only
}

type CompletionResponse struct {
	Content string `json:"content"`
	Tokens  int    `json:"tokens"`
}

type ModelProvider interface {
	Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
	Embed(ctx context.Context, texts []string) ([][]float32, error)
	Health(ctx context.Context) error
	Name() string
}

// MockProvider provides a deterministic fallback for testing.
type MockProvider struct{}

func NewMockProvider() *MockProvider {
	return &MockProvider{}
}

func (m *MockProvider) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	// Simple deterministic response
	return CompletionResponse{
		Content: "mock response",
		Tokens:  2,
	}, nil
}

func (m *MockProvider) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	res := make([][]float32, len(texts))
	for i := range texts {
		res[i] = []float32{0.1, 0.2, 0.3}
	}
	return res, nil
}

func (m *MockProvider) Health(ctx context.Context) error {
	return nil
}

func (m *MockProvider) Name() string {
	return "MockProvider"
}
