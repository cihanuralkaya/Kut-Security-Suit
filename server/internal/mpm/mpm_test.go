package mpm

import (
	"reflect"
	"sort"
	"testing"
)

// sortedMatches, indeks kümesini deterministik karşılaştırma için sıralar.
func sortedMatches(m *Matcher, text string) []int {
	got := m.Matches(text)
	sort.Ints(got)
	return got
}

func TestMatches_Basic(t *testing.T) {
	m := Build([]string{"mimikatz", "psexec", "nc.exe"})
	got := sortedMatches(m, "process launched: C:\\tools\\PsExec.exe -s cmd")
	want := []int{1} // psexec (küçük/büyük harf duyarsız)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Matches = %v, want %v", got, want)
	}
	if !m.MatchAny("run mimikatz now") {
		t.Fatal("MatchAny should find mimikatz")
	}
	if m.MatchAny("nothing suspicious here") {
		t.Fatal("MatchAny should not match benign text")
	}
}

// TestMatches_OverlappingSuffix, Aho-Corasick'in ayırt edici davranışını test eder:
// bir desen, başka bir desenin/ metnin SON-EKİ olduğunda fail-bağlantısı üzerinden
// yine de bulunmalı. "he", "she", "his", "hers" klasik örneği.
func TestMatches_OverlappingSuffix(t *testing.T) {
	pats := []string{"he", "she", "his", "hers"}
	m := Build(pats)
	got := sortedMatches(m, "ushers")
	// "ushers" içinde: "she" (u_she_rs), "he" (us_he_rs), "hers" (us_hers).
	want := []int{0, 1, 3} // he, she, hers
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Matches(ushers) = %v, want %v", got, want)
	}
}

func TestMatches_MultipleDistinct(t *testing.T) {
	m := Build([]string{"powershell", "-enc", "certutil"})
	got := sortedMatches(m, "powershell -enc AAAA ; certutil -urlcache")
	want := []int{0, 1, 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Matches = %v, want %v", got, want)
	}
}

func TestMatches_IndexAlignsWithInput(t *testing.T) {
	// Boş desenler indeks kaymasına yol açmamalı: dönen indeks, giriş dilimindeki
	// indeksle birebir aynı olmalı.
	m := Build([]string{"", "alpha", "", "beta"})
	got := sortedMatches(m, "see beta here")
	want := []int{3} // "beta" giriş indeksi 3
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Matches = %v, want %v (boş desen indeks kaydırmamalı)", got, want)
	}
	if m.PatternCount() != 4 {
		t.Fatalf("PatternCount = %d, want 4", m.PatternCount())
	}
}

func TestMatches_Empty(t *testing.T) {
	m := Build(nil)
	if m.MatchAny("anything") {
		t.Fatal("boş matcher hiçbir şeyle eşleşmemeli")
	}
	if got := m.Matches("anything"); got != nil {
		t.Fatalf("Matches = %v, want nil", got)
	}
	m2 := Build([]string{"", ""})
	if m2.MatchAny("anything") {
		t.Fatal("yalnız boş desenli matcher eşleşmemeli")
	}
}

func TestMatches_FirstOccurrenceOrder(t *testing.T) {
	// Matches, ilk-görülme sırasını korumalı (deterministik).
	m := Build([]string{"world", "hello"})
	got := m.Matches("hello world hello")
	want := []int{1, 0} // önce hello(1), sonra world(0)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Matches = %v, want %v (ilk-görülme sırası)", got, want)
	}
}

// TestMatches_DuplicatePatterns, aynı literalin birden fazla indekste geçmesi
// (farklı kurallar aynı ankraja sahip olabilir) her ikisini de bildirmeli.
func TestMatches_DuplicatePatterns(t *testing.T) {
	m := Build([]string{"scan", "scan"})
	got := sortedMatches(m, "port scan detected")
	want := []int{0, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Matches = %v, want %v (yinelenen desen iki indeks vermeli)", got, want)
	}
}
