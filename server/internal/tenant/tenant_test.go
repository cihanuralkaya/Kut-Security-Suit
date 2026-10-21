package tenant

import (
	"context"
	"testing"
)

func TestValid(t *testing.T) {
	ok := []string{"default", "acme", "acme-corp", "t1", "a", "musteri-42"}
	bad := []string{"", "-acme", "acme-", "Acme", "acme_corp", "acme.corp", "çok", "a b",
		"0123456789012345678901234567890123456789012345678901234567890123456"} // >63
	for _, s := range ok {
		if !Valid(s) {
			t.Errorf("Valid(%q) = false, beklenen true", s)
		}
	}
	for _, s := range bad {
		if Valid(s) {
			t.Errorf("Valid(%q) = true, beklenen false", s)
		}
	}
}

func TestNormalize(t *testing.T) {
	// Boş → Default.
	if id, err := Normalize("  "); err != nil || id != Default {
		t.Fatalf("boş → Default beklenirdi, %q %v", id, err)
	}
	// Büyük harf + boşluk kırpma.
	if id, err := Normalize("  ACME  "); err != nil || id != ID("acme") {
		t.Fatalf("normalize başarısız, %q %v", id, err)
	}
	// Geçersiz.
	if _, err := Normalize("bad_id"); err != ErrInvalid {
		t.Fatalf("geçersiz → ErrInvalid beklenirdi, %v", err)
	}
}

func TestContextRoundTrip(t *testing.T) {
	// Boş bağlam → Default.
	if got := FromContext(context.Background()); got != Default {
		t.Fatalf("boş bağlam → Default beklenirdi, %q", got)
	}
	ctx := WithTenant(context.Background(), ID("acme"))
	if got := FromContext(ctx); got != ID("acme") {
		t.Fatalf("bağlamdan acme beklenirdi, %q", got)
	}
}

func TestEquivalentTreatsLegacyEmptyAsDefault(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "default", true},
		{"default", "", true},
		{"", "", true},
		{"default", "default", true},
		{"", "acme", false}, // legacy '' yalnız default ile eşdeğer, gerçek kiracıyla DEĞİL
		{"acme", "", false},
		{"acme", "globex", false},
		{"acme", "acme", true},
	}
	for _, c := range cases {
		if got := Equivalent(c.a, c.b); got != c.want {
			t.Errorf("Equivalent(%q,%q)=%v, want %v", c.a, c.b, got, c.want)
		}
	}
}
