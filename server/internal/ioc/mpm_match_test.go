package ioc

import (
	"fmt"
	"strings"
	"testing"
)

// TestMatchMessageMPM_ManyIndicators, çok sayıda gösterge yüklendiğinde mesaj-alt-dize
// eşleşmesinin (Aho-Corasick yolu) doğru göstergeyi bulduğunu ve eşleşmeyeni
// reddettiğini doğrular.
func TestMatchMessageMPM_ManyIndicators(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "indicator-%04d.example  feed-%d\n", i, i)
	}
	// Aranan gerçek gösterge listenin ortasında.
	b.WriteString("evil-c2.example.com  known-c2 conf=high src=abuse.ch\n")
	set, err := Load(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	ind, val, ok := set.MatchIndicator(nil, "beacon to https://evil-c2.example.com/gate.php seen")
	if !ok || val != "evil-c2.example.com" {
		t.Fatalf("gösterge bulunamadı: ind=%+v val=%q ok=%v", ind, val, ok)
	}
	if ind.Label != "known-c2" || ind.Confidence != "high" || ind.Source != "abuse.ch" {
		t.Fatalf("zenginleştirme kaybı: %+v", ind)
	}
	if _, _, ok := set.MatchIndicator(nil, "tamamen zararsız bir mesaj"); ok {
		t.Fatal("eşleşmeyen mesaj için eşleşme dönmemeli")
	}
}

// TestMatchMessageMPM_Deterministic, aynı küme + mesaj için sonucun deterministik
// olduğunu (metinde en erken biten gösterge) doğrular — eski map iterasyonunun
// nondeterministik sırasına karşı iyileştirme.
func TestMatchMessageMPM_Deterministic(t *testing.T) {
	set, err := Load(strings.NewReader("alpha  a\nbeta  b\ngamma  g\n"))
	if err != nil {
		t.Fatal(err)
	}
	// "gamma" mesajda "beta"dan önce biter → gamma dönmeli, her çağrıda aynı.
	msg := "xx gamma yy beta zz alpha"
	first, val, ok := set.MatchIndicator(nil, msg)
	if !ok {
		t.Fatal("eşleşme bekleniyordu")
	}
	if val != "gamma" {
		t.Fatalf("en erken biten gösterge 'gamma' beklendi, %q döndü", val)
	}
	for i := 0; i < 20; i++ {
		_, v, _ := set.MatchIndicator(nil, msg)
		if v != val {
			t.Fatalf("sonuç deterministik değil: %q vs %q", v, val)
		}
	}
	_ = first
}

// TestMatchMessageMPM_CaseInsensitive, büyük/küçük harf duyarsızlığının korunduğunu
// doğrular (gösterge küçük harfe normalize; mesaj karışık).
func TestMatchMessageMPM_CaseInsensitive(t *testing.T) {
	set, err := Load(strings.NewReader("EvilDomain.COM  bad\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, val, ok := set.MatchIndicator(nil, "connect to EVILDOMAIN.com now"); !ok || val != "evildomain.com" {
		t.Fatalf("duyarsız eşleşme başarısız: val=%q ok=%v", val, ok)
	}
}

// BenchmarkMatchMessage, çok göstergeli mesaj taramasının başarımını ölçer
// (Aho-Corasick'in gösterge-sayısından bağımsızlığını gösterir).
func BenchmarkMatchMessage(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&sb, "bad-%05d.example  feed\n", i)
	}
	set, _ := Load(strings.NewReader(sb.String()))
	msg := "uzun bir olay mesajı içinde bad-01999.example gibi bir gösterge gizli olabilir"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.MatchIndicator(nil, msg)
	}
}
