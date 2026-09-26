// Package archive (enterprise seam), soğuk-yol (cold path) uzun-dönem arşiv için nesne-depo
// arayüzünü tanımlar — sıcak analitik (ClickHouse) yanında, olay/denetim yığınlarının
// sıkıştırılmış olarak S3-uyumlu depoya yazıldığı katman (CrowdStrike'ın S3'e replikasyon
// deseni). Bu DOSYA build-tag'siz nötrdür (arayüz); gerçek implementasyon (S3/MinIO)
// `//go:build enterprise` arkasındadır. Lite hiçbir zaman bir Archive oluşturmaz.
package archive

import "context"

// Archive, anahtar-adresli nesne depolamasıdır (S3-uyumlu). Değerler ham baytlardır;
// serileştirme/sıkıştırma (Parquet/JSONL+zstd) çağıran katmanın işidir. Contract:
// implementasyonlar (S3/MinIO, ileride başka) bu imzayı uygular.
type Archive interface {
	// Put, key altında data'yı yazar (varsa üzerine yazar).
	Put(ctx context.Context, key string, data []byte) error
	// Get, key'deki nesneyi okur. Yoksa hata döner.
	Get(ctx context.Context, key string) ([]byte, error)
	// List, prefix ile başlayan anahtarları döner (özyinelemeli).
	List(ctx context.Context, prefix string) ([]string, error)
	// Delete, key'deki nesneyi siler (retention/KVKK silme). Yoksa hata döndürmez.
	Delete(ctx context.Context, key string) error
}
