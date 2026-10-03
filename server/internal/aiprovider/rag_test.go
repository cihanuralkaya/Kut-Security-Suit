package aiprovider

import (
	"context"
	"strings"
	"testing"
)

func TestCosineSimilarity(t *testing.T) {
	v1 := []float32{1.0, 0.0, 0.0}
	v2 := []float32{1.0, 0.0, 0.0}
	v3 := []float32{0.0, 1.0, 0.0}

	sim1 := CosineSimilarity(v1, v2)
	if sim1 < 0.99 {
		t.Errorf("expected identical vectors to have similarity ~1.0, got %f", sim1)
	}

	sim2 := CosineSimilarity(v1, v3)
	if sim2 != 0.0 {
		t.Errorf("expected orthogonal vectors to have similarity 0.0, got %f", sim2)
	}

	// Mismatched lengths
	if CosineSimilarity(v1, []float32{1.0}) != 0.0 {
		t.Error("expected 0 for mismatched lengths")
	}
}

func TestRAGStore_IndexAndSearch(t *testing.T) {
	store := NewRAGStore()

	doc1 := KnowledgeDoc{
		ID:        "mitre-t1059",
		Title:     "Command and Scripting Interpreter (T1059)",
		Content:   "Adversaries may abuse command and script interpreters such as PowerShell or bash to execute arbitrary commands.",
		Category:  "mitre",
		Embedding: []float32{0.9, 0.1, 0.0},
	}

	doc2 := KnowledgeDoc{
		ID:        "runbook-ransomware",
		Title:     "Ransomware Rapid Containment Runbook",
		Content:   "Immediately isolate endpoint from network, extract volatile memory, and terminate suspect process tree.",
		Category:  "runbook",
		Embedding: []float32{0.1, 0.8, 0.2},
	}

	if err := store.Index(doc1); err != nil {
		t.Fatalf("failed to index doc1: %v", err)
	}
	if err := store.Index(doc2); err != nil {
		t.Fatalf("failed to index doc2: %v", err)
	}

	// Vector search closest to doc1
	queryEmb := []float32{0.85, 0.15, 0.0}
	results := store.SearchVector(queryEmb, 2, 0.5)

	if len(results) == 0 {
		t.Fatal("expected search results, got 0")
	}
	if results[0].Doc.ID != "mitre-t1059" {
		t.Errorf("expected top result to be mitre-t1059, got %s", results[0].Doc.ID)
	}

	// Keyword search
	kwResults := store.SearchKeyword("ransomware", 1)
	if len(kwResults) != 1 || kwResults[0].Doc.ID != "runbook-ransomware" {
		t.Errorf("expected keyword match for ransomware runbook, got %+v", kwResults)
	}

	// Prompt augmentation
	prompt := "How do I respond to host ws-01 infection?"
	augmented := store.AugmentPrompt(context.Background(), prompt, kwResults)

	if !strings.Contains(augmented, "SECURITY KNOWLEDGE CONTEXT") {
		t.Error("expected augmented context header")
	}
	if !strings.Contains(augmented, "Ransomware Rapid Containment Runbook") {
		t.Error("expected runbook title in augmented prompt")
	}
	if !strings.Contains(augmented, prompt) {
		t.Error("expected original prompt in augmented text")
	}
}
