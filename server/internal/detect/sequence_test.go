package detect

import (
	"strings"
	"testing"

	"kut.corp/suite/server/internal/model"
)

func TestMatchSequence_Order(t *testing.T) {
	msg := strings.ToLower("powershell -c IEX (New-Object Net.WebClient).DownloadString('h'); Invoke-Expr")
	// Sırayla var:
	if !matchSequence(msg, []string{"powershell", "downloadstring", "invoke"}, 0) {
		t.Fatal("sıralı literaller eşleşmeliydi")
	}
	// Yanlış sıra (invoke, downloadstring) — eşleşmemeli:
	if matchSequence(msg, []string{"powershell", "invoke", "downloadstring"}, 0) {
		t.Fatal("sıra bozuksa eşleşmemeliydi")
	}
	// Eksik literal:
	if matchSequence(msg, []string{"powershell", "mimikatz"}, 0) {
		t.Fatal("eksik literal varken eşleşmemeliydi")
	}
}

func TestMatchSequence_Within(t *testing.T) {
	msg := "aaa TOKENX bbbbbbbbbb TOKENY zzz" // X ve Y arası ~10 bayt boşluk
	lower := strings.ToLower(msg)
	// Boşluk 'bbbbbbbbbb '(11) civarı; within=5 → çok uzak, eşleşmemeli.
	if matchSequence(lower, []string{"tokenx", "tokeny"}, 5) {
		t.Fatal("within=5 çok küçük; eşleşmemeliydi")
	}
	// within=40 → yeterince geniş, eşleşmeli.
	if !matchSequence(lower, []string{"tokenx", "tokeny"}, 40) {
		t.Fatal("within=40 geniş; eşleşmeliydi")
	}
	// within=0 → boşluk kısıtı yok, yalnız sıra; eşleşmeli.
	if !matchSequence(lower, []string{"tokenx", "tokeny"}, 0) {
		t.Fatal("within=0 (sınırsız) eşleşmeliydi")
	}
}

// TestMatchSequence_WithinSoundness, within kısıtında SAĞLAMLIĞI (complete) doğrular:
// önceki literalin daha GEÇ bir oluşumu, sonrakini yakınlık penceresine sokabildiğinde
// eşleşme bulunmalı (greedy en-erken bunu kaçırırdı → tespit atlatma açığı).
func TestMatchSequence_WithinSoundness(t *testing.T) {
	// seq ab→xy, within 1: ab@0 ile xy@9 uzak (boşluk 7) ama ab@7 ile xy@9 boşluk 0.
	if !matchSequence("abzzzzzabxy", []string{"ab", "xy"}, 1) {
		t.Fatal("geç ab oluşumu xy'yi pencereye sokuyor; eşleşmeliydi (sağlamlık)")
	}
	// Gerçekten uzaksa eşleşmemeli: tek ab@0, xy çok uzakta.
	if matchSequence("abxxxxxxxxxxxxxy", []string{"ab", "xy"}, 1) {
		t.Fatal("yalnız uzak oluşum var; eşleşmemeliydi")
	}
	// Üç literal zinciri, her boşluk within içinde ama ilk literalin geç oluşumu gerekli.
	if !matchSequence("a....a.b.c", []string{"a", "b", "c"}, 2) {
		t.Fatal("a@5,b@7,c@9 zinciri within=2 ile eşleşmeliydi")
	}
	// Bitişik (boşluk 0) within=0 kenar durumu ayrı testte; burada within>0 adjacency:
	if !matchSequence("abcd", []string{"ab", "cd"}, 0) {
		t.Fatal("within=0 sınırsız; sıralı ab,cd eşleşmeliydi")
	}
}

func TestMatchSequence_GreedyEarliestSound(t *testing.T) {
	// İlk "ab" konumu within'i aşsa bile, monotonluk nedeniyle sonraki konumlar da
	// aşar — greedy en-erken arama doğru sonucu verir (yanlış-pozitif üretmez).
	msg := "ab xxxxxxxxxx cd"
	if matchSequence(msg, []string{"ab", "cd"}, 3) {
		t.Fatal("boşluk 11 > within 3; eşleşmemeliydi")
	}
}

// TestSequenceEquivalence, Sequence taşıyan kuralda ön-filtreli (Evaluate) ve
// doğrusal (linearEval) sonuçların özdeş kaldığını doğrular (prefilter soundness).
func TestSequenceEquivalence(t *testing.T) {
	rules := []Rule{
		{ID: "SEQ-1", Name: "indir-çalıştır zinciri", Category: "PROCESS",
			Sequence: []string{"powershell", "downloadstring", "invoke"}, Severity: "HIGH"},
		{ID: "SEQ-2", Name: "yakınlık", Category: "PROCESS",
			Sequence: []string{"certutil", "urlcache"}, WithinBytes: 20, Severity: "HIGH"},
	}
	e := NewEngine(rules)
	events := []model.Event{
		{Category: "PROCESS", Message: "powershell IEX DownloadString then Invoke-Expression", Severity: "HIGH"},
		{Category: "PROCESS", Message: "powershell only, no download", Severity: "HIGH"},
		{Category: "PROCESS", Message: "invoke before downloadstring powershell (yanlış sıra)", Severity: "HIGH"},
		{Category: "PROCESS", Message: "certutil -urlcache -f http://x", Severity: "HIGH"},
		{Category: "PROCESS", Message: "certutil ................................ urlcache (uzak)", Severity: "HIGH"},
		{Category: "PROCESS", Message: "alakasız metin", Severity: "HIGH"},
	}
	for i, ev := range events {
		want := linearEval(e, ev)
		got := e.Evaluate(ev)
		if len(want) != len(got) {
			t.Errorf("olay[%d] %q: Evaluate=%v linear=%v", i, ev.Message, got, want)
			continue
		}
		for j := range want {
			if want[j].RuleID != got[j].RuleID {
				t.Errorf("olay[%d] %q: sıra farkı Evaluate=%v linear=%v", i, ev.Message, got, want)
			}
		}
	}
}

func TestSequenceValidation(t *testing.T) {
	bad := []string{
		`[{"id":"X","name":"n","severity":"HIGH","within_bytes":-1}]`,
		`[{"id":"X","name":"n","severity":"HIGH","within_bytes":10,"sequence":["only-one"]}]`,
	}
	for i, b := range bad {
		if _, err := LoadRules(strings.NewReader(b)); err == nil {
			t.Errorf("geçersiz sequence[%d] kabul edildi", i)
		}
	}
	good := `[{"id":"X","name":"n","severity":"HIGH","sequence":["a","b"],"within_bytes":10}]`
	if _, err := LoadRules(strings.NewReader(good)); err != nil {
		t.Fatalf("geçerli sequence reddedildi: %v", err)
	}
}
