package authtoken

import (
	"testing"
	"time"
)

func TestMemStore_CreateVerifyRevoke(t *testing.T) {
	s := NewMemStore(nil)
	id, secret, err := s.Create(ScopeMetrics, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Verify(ScopeMetrics, secret) {
		t.Fatal("geçerli sır doğrulanmalı")
	}
	// Yanlış sır / yanlış kapsam reddedilmeli.
	if s.Verify(ScopeMetrics, "yanlis") {
		t.Fatal("yanlış sır doğrulanmamalı")
	}
	if s.Verify(ScopeIngest, secret) {
		t.Fatal("kapsam uyuşmazlığı doğrulanmamalı")
	}
	// İptal sonrası reddedilmeli.
	if err := s.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if s.Verify(ScopeMetrics, secret) {
		t.Fatal("iptal edilen token doğrulanmamalı")
	}
	if err := s.Revoke("yok"); err != ErrNotFound {
		t.Fatalf("bilinmeyen id iptali ErrNotFound dönmeli: %v", err)
	}
}

func TestMemStore_Expiry(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0).UTC()
	s := NewMemStore(func() time.Time { return clk })
	_, secret, _ := s.Create(ScopeIngest, 60*time.Second)
	if !s.Verify(ScopeIngest, secret) {
		t.Fatal("süresi dolmadan geçerli olmalı")
	}
	clk = clk.Add(61 * time.Second)
	if s.Verify(ScopeIngest, secret) {
		t.Fatal("süresi dolan token reddedilmeli")
	}
}

func TestMemStore_ListNoSecret(t *testing.T) {
	s := NewMemStore(nil)
	s.Create(ScopeMetrics, 0)
	s.Create(ScopeIngest, 0)
	all, _ := s.List("")
	if len(all) != 2 {
		t.Fatalf("2 token beklendi, %d", len(all))
	}
	only, _ := s.List(ScopeMetrics)
	if len(only) != 1 || only[0].Scope != ScopeMetrics {
		t.Fatalf("kapsam filtresi yanlış: %+v", only)
	}
	// List sır/özet döndürmemeli (Token tipi zaten içermez — derleme-zamanı garanti).
}

func TestVerify_UsesLastUsed(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0).UTC()
	s := NewMemStore(func() time.Time { return clk })
	_, secret, _ := s.Create(ScopeMetrics, 0)
	s.Verify(ScopeMetrics, secret)
	list, _ := s.List(ScopeMetrics)
	if list[0].LastUsedAt == nil {
		t.Fatal("doğrulama LastUsedAt'i güncellemeli")
	}
}
