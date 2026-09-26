// Package analytics (enterprise seam), yüksek-hacimli olay analitiği için depolama
// arayüzünü tanımlar. Bu DOSYA build-tag'siz nötrdür (yalnız arayüz + tipler) ki paket
// Lite'ta da derlensin; gerçek implementasyon (ClickHouse) `//go:build enterprise` arkasındadır.
// Lite hiçbir zaman bir AnalyticsStore oluşturmaz — çekirdek analitiği Postgres'te kalır.
package analytics

import (
	"context"
	"time"

	"kut.corp/suite/server/internal/model"
)

// AnalyticsStore, kanonik olayları toplu yazan ve analitik sorgular çalıştıran ölçekli
// depodur (Enterprise). Contract: implementasyonlar (ClickHouse, ileride başka) bu imzayı
// uygular; çağıranlar yalnız bu arayüze bağlanır (dosya-bus'taki DurableLog deseni gibi).
type AnalyticsStore interface {
	// Insert, olayları toplu (batch) yazar. Boş dilim no-op'tur. Yazmadan önce her olayın
	// kararlı EventID'si güvence altına alınır (idempotens temeli).
	Insert(ctx context.Context, events []model.Event) error
	// CountBySeverity, verilen andan (dahil) itibaren olayları önem düzeyine göre sayar —
	// temsili bir agregasyon sorgusu (konsol önem grafiğinin ölçekli karşılığı).
	CountBySeverity(ctx context.Context, since time.Time) (map[string]uint64, error)
	// Close, bağlantıyı kapatır. Idempotenttir.
	Close() error
}
