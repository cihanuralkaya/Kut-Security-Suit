package aibrain

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// Eşzamanlılık (CI -race ile koşar): paralel Observe/Score/Prune/Stats veri yarışı üretmemeli
// ve kaynak tavanı aşılmamalı.
func TestSeqModelsConcurrentAccess(t *testing.T) {
	r := NewSeqModels()
	r.SetLimits(SeqLimits{MaxSources: 50})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			tn := "t" + strconv.Itoa(w%3)
			for i := 0; i < 1500; i++ {
				toks := []string{"root", "p" + strconv.Itoa(i%200), "leaf" + strconv.Itoa(i)}
				r.Observe(tn, toks)
				if i%25 == 0 {
					_ = r.Score(tn, toks)
					_ = r.Stats()
					_ = r.Tenants()
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			r.Prune(time.Now().Add(-time.Hour))
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	for _, tn := range r.Tenants() {
		_ = r.Score(tn, []string{"root", "p1"})
	}
	if s := r.Stats(); s.Sources > 3*50 {
		t.Fatalf("kaynak tavanı (kiracı başına 50) aşılmamalı: %+v", s)
	}
}
