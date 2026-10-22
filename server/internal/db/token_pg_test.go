package db

// Yönetilen ingest token'ının kiracı bağı — gerçek PostgreSQL'e karşı. KUT_DATABASE_URL
// yoksa ATLANIR (CI'daki "DB yolu (PostgreSQL)" işi koşturur).

import (
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/authtoken"
)

func TestPGIngestTokenTenantBinding(t *testing.T) {
	s, ctx := pgStore(t)
	ts := s.TokenStore()
	tn := uniq(t, "tn-")

	idBound, secBound, err := ts.CreateForTenant(authtoken.ScopeIngest, tn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	idLegacy, secLegacy, err := ts.Create(authtoken.ScopeIngest, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM tokens WHERE id IN ($1::uuid, $2::uuid)`, idBound, idLegacy)
	})

	// POZİTİF: kiracıya bağlı token kendi kiracısını döndürür; SQL'de saklanan sütun doğru.
	if got, ok := ts.VerifyTenant(authtoken.ScopeIngest, secBound); !ok || got != tn {
		t.Fatalf("bağlı token kiracısını döndürmeli: %q %v", got, ok)
	}
	var stored string
	if err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM tokens WHERE id = $1::uuid`, idBound).Scan(&stored); err != nil || stored != tn {
		t.Fatalf("tenant_id sütunu bağlı kiracıyı taşımalı: %q %v", stored, err)
	}
	// POZİTİF: legacy token kiracısız doğrulanır (Verify de geçer).
	if got, ok := ts.VerifyTenant(authtoken.ScopeIngest, secLegacy); !ok || got != "" {
		t.Fatalf("legacy token kiracısız doğrulanmalı: %q %v", got, ok)
	}
	if !ts.Verify(authtoken.ScopeIngest, secLegacy) {
		t.Fatal("kiracısız token Verify ile geçmeli")
	}

	// NEGATİF: kiracı-kör Verify kiracıya bağlı token'ı kabul etmez; yanlış kapsam; boş sır.
	if ts.Verify(authtoken.ScopeIngest, secBound) {
		t.Fatal("kiracı-kör Verify, bağlı token'ı kabul etmemeli")
	}
	if _, ok := ts.VerifyTenant(authtoken.ScopeMetrics, secBound); ok {
		t.Fatal("ingest token'ı metrics kapsamında geçmemeli")
	}
	if _, ok := ts.VerifyTenant(authtoken.ScopeIngest, ""); ok {
		t.Fatal("boş sır geçmemeli")
	}
	// NEGATİF: metrics kapsamı kiracı bağı taşıyamaz; geçersiz biçim reddedilir.
	if _, _, err := ts.CreateForTenant(authtoken.ScopeMetrics, tn, 0); !errors.Is(err, authtoken.ErrInvalidTenantBinding) {
		t.Fatalf("metrics + kiracı reddedilmeli: %v", err)
	}
	if _, _, err := ts.CreateForTenant(authtoken.ScopeIngest, "Bad Tenant!", 0); !errors.Is(err, authtoken.ErrInvalidTenantBinding) {
		t.Fatalf("geçersiz kiracı biçimi reddedilmeli: %v", err)
	}

	// Liste kiracıyı gösterir; iptal sonrası doğrulama düşer.
	list, err := ts.List(authtoken.ScopeIngest)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tok := range list {
		if tok.ID == idBound {
			found = tok.Tenant == tn
		}
	}
	if !found {
		t.Fatal("liste bağlı kiracıyı göstermeli")
	}
	if err := ts.Revoke(idBound); err != nil {
		t.Fatal(err)
	}
	if _, ok := ts.VerifyTenant(authtoken.ScopeIngest, secBound); ok {
		t.Fatal("iptal edilen token geçmemeli")
	}
}
