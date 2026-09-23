package db

import (
	"context"
	"fmt"
	"time"

	"kut.corp/suite/server/internal/model"
)

// MarkStaleOffline, belirtilen zamandan daha eski last_seen'e sahip ACTIVE
// cihazları OFFLINE olarak işaretler ve etkilenen satır sayısını döner.
// Yalnız ACTIVE cihazlara dokunur: QUARANTINED gibi diğer durumlar korunur
// (karantinadaki bir cihaz heartbeat kesse de OFFLINE'a düşmez).
func (s *Store) MarkStaleOffline(ctx context.Context, olderThan time.Time) (int, error) {
	const q = `
		UPDATE devices
		   SET status = 'OFFLINE'
		 WHERE last_seen < $1
		   AND status = 'ACTIVE'`
	tag, err := s.pool.Exec(ctx, q, olderThan)
	if err != nil {
		return 0, fmt.Errorf("db: bayat cihaz işaretleme: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// SetDeviceStatus, bir cihazın durumunu doğrudan verilen değere ayarlar
// (admin aksiyonlarının yansıması: QUARANTINED / ACTIVE). status device_status
// enum'una cast edilir; geçersiz değer DB tarafından reddedilir.
// ApplyCommandResults, başarılı karantina sonuçlarında EFFECTIVE cihaz durumunu ayarlar
// (F-D). QUARANTINE OK → QUARANTINED; UNQUARANTINE OK → ACTIVE. Başarısız/ilgisiz
// sonuçlar durumu değiştirmez.
func (s *Store) ApplyCommandResults(ctx context.Context, deviceID string, outcomes []model.CommandOutcome) error {
	const q = `UPDATE devices SET status = $2::device_status WHERE id = $1`
	for _, o := range outcomes {
		if !o.OK {
			continue
		}
		var st string
		switch o.Type {
		case "QUARANTINE":
			st = "QUARANTINED"
		case "UNQUARANTINE":
			st = "ACTIVE"
		default:
			continue
		}
		if _, err := s.pool.Exec(ctx, q, deviceID, st); err != nil {
			return fmt.Errorf("db: effective durum güncelleme: %w", err)
		}
	}
	return nil
}

func (s *Store) SetDeviceStatus(ctx context.Context, deviceID, status string) error {
	const q = `UPDATE devices SET status = $2::device_status WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, deviceID, status); err != nil {
		return fmt.Errorf("db: cihaz durumu ayarlama: %w", err)
	}
	return nil
}
