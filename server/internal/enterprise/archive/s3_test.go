//go:build enterprise

package archive

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// s3TestArchive, entegrasyon testleri için bir Archive kurar; KUT_S3_ENDPOINT ayarlı değilse
// test atlanır (S3/MinIO gömülemez → CI'da MinIO konteyneri sağlar). Her koşu için benzersiz kova.
func s3TestArchive(t *testing.T) *s3Archive {
	t.Helper()
	endpoint := os.Getenv("KUT_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("KUT_S3_ENDPOINT ayarlı değil; S3 entegrasyon testi atlandı (CI'da MinIO konteyneri sağlar)")
	}
	bucket := fmt.Sprintf("kut-test-%d", time.Now().UnixNano())
	a, err := NewS3Archive(endpoint, os.Getenv("KUT_S3_ACCESS_KEY"), os.Getenv("KUT_S3_SECRET_KEY"), bucket, false)
	if err != nil {
		t.Fatalf("NewS3Archive: %v", err)
	}
	return a
}

// Put/Get/List/Delete uçtan uca yaşam döngüsü.
func TestS3PutGetListDelete(t *testing.T) {
	a := s3TestArchive(t)
	ctx := context.Background()

	key := "events/2026/09/batch-001.jsonl"
	payload := []byte(`{"event_id":"evt_1","severity":"high"}` + "\n")

	if err := a.Put(ctx, key, payload); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := a.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get içerik uyuşmadı: got %q want %q", got, payload)
	}

	keys, err := a.List(ctx, "events/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, k := range keys {
		if k == key {
			found = true
		}
	}
	if !found {
		t.Fatalf("List anahtarı içermiyor: %v", keys)
	}

	if err := a.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := a.Get(ctx, key); err == nil {
		t.Fatal("silinen nesne hâlâ okunabiliyor (hata bekleniyordu)")
	}
}

// Var olmayan anahtarın silinmesi hata döndürmemeli (S3 idempotent silme semantiği).
func TestS3DeleteMissing(t *testing.T) {
	a := s3TestArchive(t)
	if err := a.Delete(context.Background(), "yok/olmayan-anahtar"); err != nil {
		t.Fatalf("olmayan anahtar silme hata döndürdü: %v", err)
	}
}
