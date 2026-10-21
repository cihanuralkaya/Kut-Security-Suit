package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"kut.corp/suite/server/internal/admin"
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
//
// S-4 derinlemesine savunma: tenantID boş değilse UPDATE token'ın mühürlü kiracısıyla
// daraltılır (`AND tenant_id = $2`); servis katmanındaki kiracı kapısı atlansa bile başka
// kiracının token'ı iptal edilemez. Boş tenantID = platform kapsamı (süzme yok). Kiracıya
// bağlı çağıran için o kiracıda böyle bir token HİÇ yoksa (yok/yabancı) ErrForbidden; kendi
// token'ı zaten kullanılmışsa sessiz no-op.
func (s *Store) RevokeEnrollmentToken(ctx context.Context, tokenID, tenantID string) error {
	const q = `UPDATE enrollment_tokens SET used_at = now()
	            WHERE id::text = $1 AND used_at IS NULL AND ($2 = '' OR tenant_id = $2)`
	ct, err := s.pool.Exec(ctx, q, tokenID, tenantID)
	if err != nil {
		return fmt.Errorf("db: enrollment token iptali: %w", err)
	}
	if tenantID != "" && ct.RowsAffected() == 0 {
		var owned bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM enrollment_tokens WHERE id::text = $1 AND tenant_id = $2)`,
			tokenID, tenantID).Scan(&owned); err != nil {
			return fmt.Errorf("db: enrollment token sahiplik: %w", err)
		}
		if !owned {
			return admin.ErrForbidden
		}
	}
	return nil
}

// EnrollmentTokenTenant, enrollment token'ın mühürlü kiracısını döner (iptal yazma-yolunun
// kiracı zorunlu-kılması için). Token yoksa found=false (hata değil).
func (s *Store) EnrollmentTokenTenant(ctx context.Context, tokenID string) (string, bool, error) {
	var tenant string
	err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM enrollment_tokens WHERE id::text = $1`, tokenID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: enrollment token kiracısı: %w", err)
	}
	return tenant, true, nil
}
