package aiprovider

import (
	"context"
	"regexp"
	"testing"
)

// BenchDataDLP is a mock DLP engine for benchmarking PII scrubbing.
type BenchDataDLP struct {
	ssnRegex *regexp.Regexp
}

func NewBenchDataDLP() *BenchDataDLP {
	return &BenchDataDLP{
		ssnRegex: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	}
}

func (dlp *BenchDataDLP) ScrubPII(input string) string {
	return dlp.ssnRegex.ReplaceAllString(input, "[REDACTED]")
}

// BenchModelRouter is a mock router for evaluating latency of model routing.
type BenchModelRouter struct{}

func (mr *BenchModelRouter) Route(ctx context.Context, tenantID, classification string) string {
	if tenantID == "" || classification == "public" {
		return "standard-model"
	}
	return "secure-isolated-model"
}

// BenchRAGStore is a mock vector database for benchmarking retrieval latency.
type BenchRAGStore struct{}

func (rs *BenchRAGStore) Search(ctx context.Context, vector []float32) []string {
	// Simulate vector search
	return []string{"doc-id-1", "doc-id-2"}
}

func BenchmarkDataDLP_ScrubPII(b *testing.B) {
	dlp := NewBenchDataDLP()
	inputContext := "The user provided their social security number 123-45-6789 during the support chat. Another SSN is 987-65-4321."

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = dlp.ScrubPII(inputContext)
	}
}

func BenchmarkModelRouter_Route(b *testing.B) {
	mr := &BenchModelRouter{}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = mr.Route(ctx, "tenant-abc", "highly-confidential")
	}
}

func BenchmarkRAGStore_Search(b *testing.B) {
	rs := &BenchRAGStore{}
	ctx := context.Background()
	vector := make([]float32, 1536) // e.g., OpenAI embedding size

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = rs.Search(ctx, vector)
	}
}
