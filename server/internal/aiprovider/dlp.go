package aiprovider

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

type DataDLP struct {
	rules []*regexp.Regexp
}

type RedactionMap struct {
	mu      sync.RWMutex
	mapping map[string]string // token -> original
}

func NewRedactionMap() *RedactionMap {
	return &RedactionMap{
		mapping: make(map[string]string),
	}
}

func (r *RedactionMap) Add(original string) string {
	b := make([]byte, 8)
	rand.Read(b)
	token := fmt.Sprintf("<REDACTED:%s>", hex.EncodeToString(b))
	
	r.mu.Lock()
	r.mapping[token] = original
	r.mu.Unlock()
	
	return token
}

func (r *RedactionMap) Get(token string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	orig, ok := r.mapping[token]
	return orig, ok
}

func NewDataDLP() *DataDLP {
	return &DataDLP{
		rules: []*regexp.Regexp{
			regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`), // Email
			regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), // IP
			regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`), // JWT
			regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), // AWS Key
			regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token)[\s:=]+['"]?[a-zA-Z0-9_\-]{16,}['"]?`), // Generic API Key
		},
	}
}

func (d *DataDLP) MapRedactions(text string, rmap *RedactionMap) string {
	for _, rule := range d.rules {
		text = rule.ReplaceAllStringFunc(text, func(match string) string {
			return rmap.Add(match)
		})
	}
	return text
}

func (d *DataDLP) Rehydrate(text string, rmap *RedactionMap) string {
	rmap.mu.RLock()
	defer rmap.mu.RUnlock()
	for token, orig := range rmap.mapping {
		text = strings.ReplaceAll(text, token, orig)
	}
	return text
}
