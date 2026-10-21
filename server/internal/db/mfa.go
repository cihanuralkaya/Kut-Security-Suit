package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// MFA (2FA) sırlarının kalıcı depolaması. TOTP sırrı, admins.mfa_secret sütununda
// AES-256-GCM (FieldCipher) ile şifreli tutulur; DB'yi ele geçiren biri sırları
// düz göremez. Şifreleyici bağlı değilse yazma reddedilir (fail-closed).

// SetPendingMFASecret, yöneticinin YENİ TOTP sırrını şifreleyip mfa_pending_secret'a
// yazar. Etkin sır (mfa_secret) ve mfa_enrolled'a DOKUNMAZ: yeniden kayıtta mevcut MFA,
// yeni sır geçerli bir kodla etkinleştirilene (ActivateMFA) dek aynen zorunlu kalır
// (kayıt penceresinde MFA'nın fiilen kapanması engellenir).
func (s *Store) SetPendingMFASecret(ctx context.Context, adminID, secret string) error {
	if s.cipher == nil {
		return errors.New("db: MFA için alan şifreleyici bağlı değil")
	}
	enc, err := s.cipher.EncryptString(secret)
	if err != nil {
		return fmt.Errorf("db: MFA sırrı şifreleme: %w", err)
	}
	const q = `UPDATE admins SET mfa_pending_secret = $2 WHERE id = $1::uuid`
	if _, err := s.pool.Exec(ctx, q, adminID, enc); err != nil {
		return fmt.Errorf("db: MFA sırrı kaydı: %w", err)
	}
	return nil
}

// LookupPendingMFA, yöneticinin bekleyen (henüz etkinleştirilmemiş) TOTP sırrını
// (çözülmüş) döner; yoksa ("", nil).
func (s *Store) LookupPendingMFA(ctx context.Context, adminID string) (string, error) {
	const q = `SELECT mfa_pending_secret FROM admins WHERE id = $1::uuid AND is_active`
	var enc []byte
	err := s.pool.QueryRow(ctx, q, adminID).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("db: bekleyen MFA arama: %w", err)
	}
	if len(enc) == 0 {
		return "", nil
	}
	if s.cipher == nil {
		return "", errors.New("db: MFA için alan şifreleyici bağlı değil")
	}
	secret, err := s.cipher.DecryptString(enc)
	if err != nil {
		return "", fmt.Errorf("db: bekleyen MFA sırrı çözme: %w", err)
	}
	return secret, nil
}

// LookupMFA, yöneticinin TOTP sırrını (çözülmüş) ve etkin durumunu döner. Sır
// yoksa ("", false, nil).
func (s *Store) LookupMFA(ctx context.Context, adminID string) (string, bool, error) {
	const q = `SELECT mfa_secret, mfa_enrolled FROM admins WHERE id = $1::uuid AND is_active`
	var enc []byte
	var enrolled bool
	err := s.pool.QueryRow(ctx, q, adminID).Scan(&enc, &enrolled)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: MFA arama: %w", err)
	}
	if len(enc) == 0 {
		return "", false, nil
	}
	if s.cipher == nil {
		return "", false, errors.New("db: MFA için alan şifreleyici bağlı değil")
	}
	secret, err := s.cipher.DecryptString(enc)
	if err != nil {
		return "", false, fmt.Errorf("db: MFA sırrı çözme: %w", err)
	}
	return secret, enrolled, nil
}

// ActivateMFA, bekleyen sırrı TEK atomik UPDATE ile etkin sır yapar: mfa_secret yeni sırra
// döner, bekleyen sütun temizlenir, mfa_enrolled=TRUE. Bekleyen sır yoksa satır
// güncellenmez (eski sır aynen geçerli kalır). Eski sır bu andan itibaren GEÇERSİZDİR.
func (s *Store) ActivateMFA(ctx context.Context, adminID string) error {
	const q = `UPDATE admins SET mfa_secret = mfa_pending_secret, mfa_pending_secret = NULL, mfa_enrolled = TRUE
	              WHERE id = $1::uuid AND mfa_pending_secret IS NOT NULL`
	if _, err := s.pool.Exec(ctx, q, adminID); err != nil {
		return fmt.Errorf("db: MFA etkinleştirme: %w", err)
	}
	return nil
}

// DisableMFA, etkin ve bekleyen TOTP sırrını siler ve MFA'yı kapatır.
func (s *Store) DisableMFA(ctx context.Context, adminID string) error {
	const q = `UPDATE admins SET mfa_secret = NULL, mfa_pending_secret = NULL, mfa_enrolled = FALSE, mfa_last_step = 0 WHERE id = $1::uuid`
	if _, err := s.pool.Exec(ctx, q, adminID); err != nil {
		return fmt.Errorf("db: MFA kapatma: %w", err)
	}
	return nil
}

// ConsumeTOTPStep, TOTP tek-kullanım (anti-replay) zorlamasıdır. Verilen adım sayacı
// yöneticinin son kabul edilen adımından BÜYÜKSE tek atomik UPDATE ile kaydeder ve
// accepted=true döner; değilse (adım <= son, yani tekrar) satır güncellenmez → false.
// Atomiklik veritabanı satır kilidiyle sağlanır (eşzamanlı tekrar tek-kazanan).
func (s *Store) ConsumeTOTPStep(ctx context.Context, adminID string, step int64) (bool, error) {
	const q = `UPDATE admins SET mfa_last_step = $2 WHERE id = $1::uuid AND $2 > mfa_last_step`
	tag, err := s.pool.Exec(ctx, q, adminID, step)
	if err != nil {
		return false, fmt.Errorf("db: TOTP adım tüketimi: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
