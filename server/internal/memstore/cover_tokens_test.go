package memstore

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/enroll"
)

// SaveEnrollmentToken + ConsumeEnrollmentToken: geçerli token bir kez tüketilir;
// ikinci tüketim, süresi geçmiş ve bilinmeyen token ErrInvalidToken döner.
func TestEnrollmentTokenConsume(t *testing.T) {
	ctx := context.Background()
	s := New()
	adminID := s.SeedAdmin("op@x", "h", "OPERATOR")

	idx := []byte("tok-index-1")
	exp := time.Now().Add(time.Hour)
	if err := s.SaveEnrollmentToken(ctx, idx, adminID, "", exp); err != nil {
		t.Fatal(err)
	}

	// İlk tüketim başarılı (boundDev boş → "" döner, hata yok).
	dev, _, err := s.ConsumeEnrollmentToken(ctx, idx, time.Now())
	if err != nil {
		t.Fatalf("geçerli token tüketilmeliydi: %v", err)
	}
	if dev != "" {
		t.Fatalf("boundDev boş olmalıydı: %q", dev)
	}

	// İkinci tüketim: used=true → ErrInvalidToken.
	if _, _, err := s.ConsumeEnrollmentToken(ctx, idx, time.Now()); err != enroll.ErrInvalidToken {
		t.Fatalf("ikinci tüketim ErrInvalidToken dönmeliydi: %v", err)
	}

	// Bilinmeyen token.
	if _, _, err := s.ConsumeEnrollmentToken(ctx, []byte("yok"), time.Now()); err != enroll.ErrInvalidToken {
		t.Fatalf("bilinmeyen token ErrInvalidToken dönmeliydi: %v", err)
	}

	// Süresi geçmiş token.
	idx2 := []byte("tok-index-2")
	if err := s.SaveEnrollmentToken(ctx, idx2, adminID, "", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ConsumeEnrollmentToken(ctx, idx2, time.Now()); err != enroll.ErrInvalidToken {
		t.Fatalf("süresi geçmiş token ErrInvalidToken dönmeliydi: %v", err)
	}
}

// RevokeEnrollmentToken: token'ı id ile bulup used=true yapar; sonrasında
// tüketilemez. Bilinmeyen id no-op.
func TestRevokeEnrollmentToken(t *testing.T) {
	ctx := context.Background()
	s := New()
	adminID := s.SeedAdmin("op@x", "h", "OPERATOR")

	idx := []byte("tok-rev")
	if err := s.SaveEnrollmentToken(ctx, idx, adminID, "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// id'yi listeden al.
	rows, err := s.ListEnrollmentTokens(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("1 token beklenirdi: %d", len(rows))
	}
	tokID := rows[0].ID

	if err := s.RevokeEnrollmentToken(ctx, tokID); err != nil {
		t.Fatal(err)
	}
	// Artık tüketilemez.
	if _, _, err := s.ConsumeEnrollmentToken(ctx, idx, time.Now()); err != enroll.ErrInvalidToken {
		t.Fatalf("iptal edilen token tüketilememeliydi: %v", err)
	}

	// Bilinmeyen id no-op (panik/hata yok).
	if err := s.RevokeEnrollmentToken(ctx, "yok"); err != nil {
		t.Fatalf("bilinmeyen id no-op olmalıydı: %v", err)
	}
}

// ListEnrollmentTokens: created_at DESC sıralı, createdBy admin id'si e-postaya
// çözülür, limit uygulanır, Used bayrağı yansır.
func TestListEnrollmentTokens(t *testing.T) {
	ctx := context.Background()
	s := New()
	adminID := s.SeedAdmin("creator@x", "h", "ADMIN")

	// Üç token; createdAt farkı için araya ufak uyku yerine artan expiry değil,
	// createdAt time.Now() ile üretildiğinden sıralamayı ID setiyle doğrularız.
	for i, idx := range [][]byte{[]byte("a"), []byte("b"), []byte("c")} {
		if err := s.SaveEnrollmentToken(ctx, idx, adminID, "", time.Now().Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}

	rows, err := s.ListEnrollmentTokens(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("3 token beklenirdi: %d", len(rows))
	}
	// created_at DESC: en yeni ilk sırada.
	for i := 1; i < len(rows); i++ {
		if rows[i-1].CreatedAt.Before(rows[i].CreatedAt) {
			t.Fatalf("created_at DESC sıralı olmalıydı: %v < %v", rows[i-1].CreatedAt, rows[i].CreatedAt)
		}
	}
	// createdBy e-postaya çözülmeli.
	if rows[0].CreatedByEmail != "creator@x" {
		t.Fatalf("createdBy e-postaya çözülmeliydi: %q", rows[0].CreatedByEmail)
	}

	// limit uygulanır.
	limited, _ := s.ListEnrollmentTokens(ctx, 2)
	if len(limited) != 2 {
		t.Fatalf("limit=2 uygulanmalıydı: %d", len(limited))
	}
}

// SaveEnrollmentToken kiracıyı saklamalı; ConsumeEnrollmentToken onu döndürmeli (çok-tenant).
func TestEnrollmentTokenCarriesTenant(t *testing.T) {
	s := New()
	ctx := context.Background()
	idx := []byte("tok-tenant-idx")
	if err := s.SaveEnrollmentToken(ctx, idx, "op1", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	dev, tenant, err := s.ConsumeEnrollmentToken(ctx, idx, time.Now())
	if err != nil {
		t.Fatalf("tüketim: %v", err)
	}
	if dev != "" || tenant != "acme" {
		t.Fatalf("kiracı taşınmadı: dev=%q tenant=%q (beklenen tenant=acme)", dev, tenant)
	}
}
