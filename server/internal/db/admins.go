package db

// Bu dosya, yönetici (admin) kullanıcı yönetiminin PostgreSQL sorgularını içerir:
// oluşturma, rol değiştirme, pasifleştirme ve listeleme. Parola hash'i (Argon2id)
// uygulama katmanında üretilir; buraya yalnız hazır hash gelir.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"kut.corp/suite/server/internal/admin"
)

// CreateAdmin, yeni bir yönetici ekler ve id'sini döner.
func (s *Store) CreateAdmin(ctx context.Context, email, passwordHash string, role admin.Role, tenantID string) (string, error) {
	const q = `
		INSERT INTO admins (email, role, password_hash, tenant_id)
		VALUES ($1, $2::admin_role, $3, $4)
		RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, email, string(role), passwordHash, tenantID).Scan(&id); err != nil {
		return "", fmt.Errorf("db: yönetici oluşturma: %w", err)
	}
	return id, nil
}

// AdminTenant, admin'in kiracısını döner (okuma izolasyonu için). Boş → platform admini
// (tüm kiracılar). Bilinmeyen, geçersiz-id'li veya PASİF yönetici için "" DÖNMEZ:
// admin.ErrUnknownAdmin döner — boş kiracı platform kapsamı olduğundan, "yok" sonucunu ""
// ile birleştirmek silinmiş/pasifleştirilmiş bir yöneticiyi platform admini yapardı (Z4b-09).
func (s *Store) AdminTenant(ctx context.Context, adminID string) (string, error) {
	if !validUUID(adminID) {
		return "", admin.ErrUnknownAdmin
	}
	var tenant string
	err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM admins WHERE id = $1::uuid AND is_active`, adminID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", admin.ErrUnknownAdmin
	}
	if err != nil {
		return "", fmt.Errorf("db: admin kiracısı: %w", err)
	}
	return tenant, nil
}

// SetAdminRole, bir yöneticinin rolünü değiştirir. S-4: tenantID boş değilse UPDATE hedefin
// kiracısıyla daraltılır (`AND tenant_id = $3`) — servis katmanındaki kapı atlansa bile bir
// kiracı başka kiracının/platformun yöneticisinin rolüne dokunamaz. Boş tenantID = platform
// kapsamı (süzme yok). Kiracıya bağlı çağıran için eşleşen yönetici yoksa ErrForbidden.
func (s *Store) SetAdminRole(ctx context.Context, id string, role admin.Role, tenantID string) error {
	if !validUUID(id) {
		return adminTargetMissing(tenantID, "yönetici rolü güncelleme")
	}
	const q = `UPDATE admins SET role = $2::admin_role WHERE id = $1::uuid AND ($3 = '' OR tenant_id = $3)`
	ct, err := s.pool.Exec(ctx, q, id, string(role), tenantID)
	if err != nil {
		return fmt.Errorf("db: yönetici rolü güncelleme: %w", err)
	}
	if tenantID != "" && ct.RowsAffected() == 0 {
		return admin.ErrForbidden
	}
	return nil
}

// DeactivateAdmin, bir yöneticiyi pasifleştirir (is_active=false). S-4: tenantID semantiği
// SetAdminRole ile aynıdır (boş = platform, doluysa hedefin kiracısı eşleşmeli).
func (s *Store) DeactivateAdmin(ctx context.Context, id, tenantID string) error {
	if !validUUID(id) {
		return adminTargetMissing(tenantID, "yönetici pasifleştirme")
	}
	const q = `UPDATE admins SET is_active = false WHERE id = $1::uuid AND ($2 = '' OR tenant_id = $2)`
	ct, err := s.pool.Exec(ctx, q, id, tenantID)
	if err != nil {
		return fmt.Errorf("db: yönetici pasifleştirme: %w", err)
	}
	if tenantID != "" && ct.RowsAffected() == 0 {
		return admin.ErrForbidden
	}
	return nil
}

// adminTargetMissing, geçersiz biçimli hedef id'si için hata üretir: kiracıya bağlı çağıran
// fail-closed ErrForbidden alır; platform çağıran açıklayıcı bir hata (eski davranış: SQL hatası).
func adminTargetMissing(tenantID, what string) error {
	if tenantID != "" {
		return admin.ErrForbidden
	}
	return fmt.Errorf("db: %s: geçersiz yönetici id", what)
}

// ListAdmins, yöneticileri e-postaya göre sıralı döner. tenantID boş değilse YALNIZ
// o kiracının yöneticileri (platform adminleri dahil değil). Parola hash'i ASLA
// seçilmez/dönmez.
func (s *Store) ListAdmins(ctx context.Context, tenantID string) ([]admin.AdminInfo, error) {
	const q = `SELECT id::text, email, role, is_active FROM admins
	             WHERE ($1 = '' OR tenant_id = $1) ORDER BY email`
	rows, err := s.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("db: yönetici listesi: %w", err)
	}
	defer rows.Close()
	var out []admin.AdminInfo
	for rows.Next() {
		var a admin.AdminInfo
		var role string
		if err := rows.Scan(&a.ID, &a.Email, &role, &a.Active); err != nil {
			return nil, fmt.Errorf("db: yönetici okuma: %w", err)
		}
		a.Role = admin.Role(role)
		out = append(out, a)
	}
	return out, rows.Err()
}
