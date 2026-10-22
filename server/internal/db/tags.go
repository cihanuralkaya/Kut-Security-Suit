package db

import (
	"context"
	"fmt"

	"kut.corp/suite/server/internal/admin"
)

// SetDeviceTags, cihazın etiketlerini (filo gruplama) değiştirir. tags nil ise
// boş diziye normalize edilir (sütun NOT NULL). pgx []string'i text[]'e eşler.
//
// Derinlemesine savunma: tenantID boş değilse UPDATE cihazın kiracısıyla daraltılır
// (`AND tenant_id = $3`); böylece servis katmanındaki bir hata kiracı sınırını aşamaz.
// Boş tenantID = platform kapsamı (süzme yok). Kiracıya bağlı çağıran için eşleşen cihaz
// yoksa (yok ya da yabancı kiracı) ErrForbidden — varlık sızdırılmaz.
func (s *Store) SetDeviceTags(ctx context.Context, deviceID string, tags []string, tenantID string) error {
	if tags == nil {
		tags = []string{}
	}
	if !validUUID(deviceID) {
		if tenantID != "" {
			return admin.ErrForbidden
		}
		return fmt.Errorf("db: cihaz etiketleri: geçersiz cihaz id")
	}
	const q = `UPDATE devices SET tags = $2 WHERE id = $1::uuid AND ($3 = '' OR tenant_id = $3)`
	ct, err := s.pool.Exec(ctx, q, deviceID, tags, tenantID)
	if err != nil {
		return fmt.Errorf("db: cihaz etiketleri: %w", err)
	}
	if tenantID != "" && ct.RowsAffected() == 0 {
		return admin.ErrForbidden
	}
	return nil
}
