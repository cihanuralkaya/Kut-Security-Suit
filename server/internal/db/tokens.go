package db

import (
	"context"
	"fmt"

	"kut.corp/suite/server/internal/adminread"
)

// ListEnrollmentTokens, enrollment token'ların meta verisini en yeniden eskiye
// listeler. Ham token asla saklanmadığından (yalnız HMAC token_hash) yalnız meta
// alanlar okunur. created_by, admins tablosuyla LEFT JOIN edilerek e-postaya
// çözülür (admin silinmiş/eşleşmemişse boş döner).
// ListEnrollmentTokens, enrollment token meta verisini döner. tenantID boş değilse
// yalnız o kiracının token'ları (enrollment_tokens.tenant_id) döner (çok-tenant izolasyonu).
func (s *Store) ListEnrollmentTokens(ctx context.Context, limit int, tenantID string) ([]adminread.EnrollmentTokenRow, error) {
	const q = `
		SELECT t.id::text, COALESCE(ad.email,''), t.expires_at,
		       (t.used_at IS NOT NULL) AS used, t.created_at
		  FROM enrollment_tokens t
		  LEFT JOIN admins ad ON ad.id = t.created_by
		 WHERE ($2 = '' OR t.tenant_id = $2)
		 ORDER BY t.created_at DESC
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit, tenantID)
	if err != nil {
		return nil, fmt.Errorf("db: enrollment token listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.EnrollmentTokenRow
	for rows.Next() {
		var t adminread.EnrollmentTokenRow
		if err := rows.Scan(&t.ID, &t.CreatedByEmail, &t.ExpiresAt, &t.Used, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: enrollment token okuma: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollmentToken, henüz kullanılmamış bir enrollment token'ı iptal eder:
// used_at'i now() ile damgalar (böylece bir sonraki kayıt denemesinde reddedilir).
// Zaten kullanılmış veya var olmayan token için hiçbir satır etkilenmez (no-op).
func (s *Store) RevokeEnrollmentToken(ctx context.Context, tokenID string) error {
	const q = `UPDATE enrollment_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL`
	_, err := s.pool.Exec(ctx, q, tokenID)
	if err != nil {
		return fmt.Errorf("db: enrollment token iptali: %w", err)
	}
	return nil
}
