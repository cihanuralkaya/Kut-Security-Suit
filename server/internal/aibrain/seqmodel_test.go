package aibrain

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// kiracı taban çizgileri BİRBİRİNDEN bağımsızdır — bir kiracının (zehirli) zinciri
// başkasının skorunu etkilemez; modeli olmayan kiracı başkasının verisine düşmez.
func TestSeqModelsPerTenantBaselines(t *testing.T) {
	r := NewSeqModels()
	for i := 0; i < 20; i++ {
		r.Observe("acme", []string{"explorer.exe", "cmd.exe"})
	}
	chain := []string{"explorer.exe", "cmd.exe"}
	if sc := r.Score("acme", chain); sc.Score != 0 {
		t.Fatalf("acme taban çizgisinde zincir sıradan olmalı: %+v", sc)
	}
	// NEGATİF: globex hiç öğrenmedi → zincir globex için tamamen nadir (acme'ye düşmez).
	if sc := r.Score("globex", chain); sc.Score != 100 {
		t.Fatalf("globex acme'nin taban çizgisini kullanmamalı: %+v", sc)
	}
	// Zehirleme: globex kendi taban çizgisine kötü zinciri öğretir; acme'nin skoru DEĞİŞMEZ.
	bad := []string{"winword.exe", "powershell.exe"}
	for i := 0; i < 50; i++ {
		r.Observe("globex", bad)
	}
	if sc := r.Score("globex", bad); sc.Score != 0 {
		t.Fatalf("globex kendi taban çizgisinde sıradan görür: %+v", sc)
	}
	if sc := r.Score("acme", bad); sc.Score != 100 {
		t.Fatalf("acme için aynı zincir nadir kalmalı (zehirleme sınırlandı): %+v", sc)
	}
	if got := r.Tenants(); len(got) != 2 {
		t.Fatalf("iki kiracı modeli beklenir: %v", got)
	}
}

// Kaynak tavanı: LRU tahliyesi çalışır, boyut tavanı aşmaz, sayaçlar artar.
func TestSeqModelSourceCapLRU(t *testing.T) {
	m := NewSeqModel()
	m.SetLimits(SeqLimits{MaxSources: 100})
	for i := 0; i < 5000; i++ {
		m.Observe([]string{"p" + strconv.Itoa(i), "child"})
	}
	st := m.Stats()
	if st.Sources > 100 || st.Evicted < 4900 {
		t.Fatalf("kaynak tavanı ve LRU tahliyesi: %+v", st)
	}
	// En yeni kaynak hâlâ biliniyor, en eskisi atılmış.
	if sc := m.Score([]string{"p4999", "child"}); sc.Score != 0 {
		t.Fatalf("en yeni kaynak korunmalı: %+v", sc)
	}
	if sc := m.Score([]string{"p0", "child"}); sc.Score != 100 {
		t.Fatalf("en eski kaynak tahliye edilmiş olmalı: %+v", sc)
	}
}

// Hedef tavanı, token uzunluğu ve dizi uzunluğu tavanları: aşan girdi öğrenilmez, sayılır.
func TestSeqModelTargetTokenAndLengthCaps(t *testing.T) {
	m := NewSeqModel()
	m.SetLimits(SeqLimits{MaxTargets: 3, MaxTokens: 4, MaxTokenLn: 8})
	for i := 0; i < 10; i++ {
		m.Observe([]string{"src", "t" + strconv.Itoa(i)})
	}
	m.mu.RLock()
	nt := len(m.trans["src"].targets)
	m.mu.RUnlock()
	if nt != 3 {
		t.Fatalf("kaynak başına hedef tavanı 3: %d", nt)
	}
	before := m.Stats().Dropped
	m.Observe([]string{"src", strings.Repeat("x", 9)}) // 9 > MaxTokenLn
	if m.Stats().Dropped != before+1 {
		t.Fatal("aşırı uzun token geçişi öğrenilmemeli ve sayılmalı")
	}
	long := make([]string, 50)
	for i := range long {
		long[i] = "n" + strconv.Itoa(i)
	}
	m.Observe(long) // 4 token'a kırpılır
	if st := m.Stats(); st.Sources > 3+4 {
		t.Fatalf("dizi uzunluğu tavanı kaynakları sınırlamalı: %+v", st)
	}
}

// TTL: Prune sunucu-saatiyle eski kaynakları atar; yeniler kalır.
func TestSeqModelPruneTTL(t *testing.T) {
	m := NewSeqModel()
	clock := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return clock }
	m.Observe([]string{"old", "x"})
	clock = clock.Add(48 * time.Hour)
	m.Observe([]string{"new", "x"})
	if n := m.Prune(clock.Add(-24 * time.Hour)); n != 1 {
		t.Fatalf("1 eski kaynak atılmalı: %d", n)
	}
	if m.Stats().Sources != 1 || m.Stats().Pruned != 1 {
		t.Fatalf("stats: %+v", m.Stats())
	}
	r := NewSeqModels()
	r.Observe("a", []string{"p", "q"})
	if r.Prune(time.Now().Add(time.Hour)) != 1 {
		t.Fatal("kayıt Prune tüm kiracılara uygulanmalı")
	}
}

// LocalProvider, SequenceInput.Tenant bölümünün taban çizgisini kullanır.
func TestLocalProviderScoresTenantPartition(t *testing.T) {
	seqs := NewSeqModels()
	for i := 0; i < 10; i++ {
		seqs.Observe("acme", []string{"a", "b"})
	}
	p := NewLocalProviderWithSeqs(seqs)
	got, _ := p.ScoreSequence(nil, SequenceInput{Tokens: []string{"a", "b"}, Tenant: "acme"})
	other, _ := p.ScoreSequence(nil, SequenceInput{Tokens: []string{"a", "b"}, Tenant: "globex"})
	if got.Score != 0 || other.Score != 100 {
		t.Fatalf("kiracı bölümü ayrımı: acme=%v globex=%v", got.Score, other.Score)
	}
}
