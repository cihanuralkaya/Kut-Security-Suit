package aiprovider

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
)

// KnowledgeDoc represents a document indexed in the security RAG store.
type KnowledgeDoc struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Content   string            `json:"content"`
	Category  string            `json:"category"` // "mitre", "runbook", "cve", "policy"
	Embedding []float32         `json:"embedding,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// SearchResult represents a retrieved document with its similarity score.
type SearchResult struct {
	Doc   KnowledgeDoc
	Score float32
}

// RAGStore manages indexing and similarity retrieval of security knowledge.
type RAGStore struct {
	mu   sync.RWMutex
	docs map[string]KnowledgeDoc
}

// NewRAGStore creates an empty in-memory RAG knowledge store.
func NewRAGStore() *RAGStore {
	return &RAGStore{
		docs: make(map[string]KnowledgeDoc),
	}
}

// Index adds or updates a knowledge document in the store.
func (s *RAGStore) Index(doc KnowledgeDoc) error {
	if strings.TrimSpace(doc.ID) == "" {
		return errors.New("document ID cannot be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[doc.ID] = doc
	return nil
}

// CosineSimilarity computes the cosine similarity between two float32 vectors.
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return float32(dot / (math.Sqrt(normA) * math.Sqrt(normB)))
}

// SearchVector retrieves the top-K most similar documents based on query embedding.
func (s *RAGStore) SearchVector(queryEmbedding []float32, topK int, minScore float32) []SearchResult {
	if len(queryEmbedding) == 0 || topK <= 0 {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []SearchResult
	for _, doc := range s.docs {
		if len(doc.Embedding) == 0 {
			continue
		}
		sim := CosineSimilarity(queryEmbedding, doc.Embedding)
		if sim >= minScore {
			results = append(results, SearchResult{
				Doc:   doc,
				Score: sim,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > topK {
		results = results[:topK]
	}
	return results
}

// SearchKeyword provides fallback lexical search over document titles and contents.
func (s *RAGStore) SearchKeyword(query string, topK int) []SearchResult {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" || topK <= 0 {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []SearchResult
	for _, doc := range s.docs {
		titleLower := strings.ToLower(doc.Title)
		contentLower := strings.ToLower(doc.Content)

		var score float32
		if strings.Contains(titleLower, query) {
			score += 0.8
		}
		if strings.Contains(contentLower, query) {
			score += 0.5
		}

		if score > 0 {
			results = append(results, SearchResult{
				Doc:   doc,
				Score: score,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > topK {
		results = results[:topK]
	}
	return results
}

// AugmentPrompt embeds relevant retrieved knowledge context into a prompt.
func (s *RAGStore) AugmentPrompt(ctx context.Context, query string, topDocs []SearchResult) string {
	if len(topDocs) == 0 {
		return query
	}

	var sb strings.Builder
	sb.WriteString("=== SECURITY KNOWLEDGE CONTEXT ===\n")
	for i, r := range topDocs {
		sb.WriteString(r.Doc.Title)
		sb.WriteString(" (Category: ")
		sb.WriteString(r.Doc.Category)
		sb.WriteString("):\n")
		sb.WriteString(r.Doc.Content)
		if i < len(topDocs)-1 {
			sb.WriteString("\n---\n")
		}
	}
	sb.WriteString("\n=== END CONTEXT ===\n\n")
	sb.WriteString(query)

	return sb.String()
}
