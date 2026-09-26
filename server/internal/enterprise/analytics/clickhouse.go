//go:build enterprise

// clickhouse.go (enterprise), AnalyticsStore'un ClickHouse implementasyonudur. ClickHouse,
// güvenlik-log analitiğinde kolonsal depolama + sıkıştırma ile Elasticsearch/OpenSearch'e
// göre çok daha kompakt/hızlıdır (bkz. Desktop araştırma raporu). Sürücü saf-Go native
// protokoldür. Import YALNIZ `//go:build enterprise` arkasında → Lite c2 bunu (ve ağır
// transitif deps'i) derlemez; zero-dep guard `clickhouse`'u reddeder.
package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"kut.corp/suite/server/internal/model"
)

const chTable = "kut_events"

// createTableDDL, kanonik model.Event alanlarını yansıtan MergeTree tablosunu oluşturur.
// Sütun sırası Insert batch'inin Append sırasıyla BİREBİR eşleşmelidir.
const createTableDDL = `CREATE TABLE IF NOT EXISTS ` + chTable + ` (
	event_id String,
	sequence UInt64,
	tenant_id String,
	device_id String,
	category LowCardinality(String),
	severity LowCardinality(String),
	event_type LowCardinality(String),
	source LowCardinality(String),
	confidence Float64,
	correlation_id String,
	parent_event_id String,
	message String,
	details String,
	occurred_at DateTime64(9, 'UTC')
) ENGINE = MergeTree
ORDER BY (tenant_id, occurred_at)`

type clickHouseStore struct {
	conn driver.Conn
}

// NewClickHouseStore, DSN'ye (ör. clickhouse://user:pass@host:9000/db) bağlanır, erişimi
// doğrular ve şemayı (yoksa) oluşturur.
func NewClickHouseStore(dsn string) (*clickHouseStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("analitik (clickhouse): KUT_CLICKHOUSE_DSN gerekli")
	}
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("analitik (clickhouse): dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("analitik (clickhouse): açılış: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("analitik (clickhouse): erişilemedi: %w", err)
	}
	if err := conn.Exec(ctx, createTableDDL); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("analitik (clickhouse): şema: %w", err)
	}
	return &clickHouseStore{conn: conn}, nil
}

// Insert, olayları tek batch'te yazar (ClickHouse toplu yazımı sever). Sütun sırası DDL ile eşleşir.
func (s *clickHouseStore) Insert(ctx context.Context, events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO "+chTable)
	if err != nil {
		return fmt.Errorf("analitik (clickhouse): batch: %w", err)
	}
	for i := range events {
		e := &events[i]
		e.EnsureID()
		if err := batch.Append(
			e.EventID, e.Sequence, e.TenantID, e.DeviceID, e.Category, e.Severity,
			e.EventType, e.Source, e.Confidence, e.CorrelationID, e.ParentEventID,
			e.Message, e.Details, e.OccurredAt.UTC(),
		); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("analitik (clickhouse): append: %w", err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("analitik (clickhouse): gönderim: %w", err)
	}
	return nil
}

// CountBySeverity, since'ten (dahil) itibaren olayları önem düzeyine göre sayar.
func (s *clickHouseStore) CountBySeverity(ctx context.Context, since time.Time) (map[string]uint64, error) {
	rows, err := s.conn.Query(ctx,
		"SELECT severity, count() AS c FROM "+chTable+" WHERE occurred_at >= ? GROUP BY severity",
		since.UTC())
	if err != nil {
		return nil, fmt.Errorf("analitik (clickhouse): sorgu: %w", err)
	}
	defer rows.Close()
	out := make(map[string]uint64)
	for rows.Next() {
		var sev string
		var c uint64
		if err := rows.Scan(&sev, &c); err != nil {
			return nil, fmt.Errorf("analitik (clickhouse): tarama: %w", err)
		}
		out[sev] = c
	}
	return out, rows.Err()
}

// Close, bağlantıyı kapatır. Idempotenttir.
func (s *clickHouseStore) Close() error {
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
