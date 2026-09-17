package db

// token.go — YÖNETİLEN API token'ları için KALICI (PostgreSQL) authtoken.Store.
// metrics/ingest uçları statik ortam token'ı yerine (ya da ona ek olarak) bu depoyu
// kullanabilir: oluştur/doğrula/iptal + süre + kapsam. Yalnız SHA-256 özeti saklanır.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"kut.corp/suite/server/internal/authtoken"
)

// tokenStore, pgx havuzu üzerinden authtoken.Store'u karşılar.
type tokenStore struct{ pool *pgxpool.Pool }

// TokenStore, DB destekli bir yönetilen-token deposu döner.
func (s *Store) TokenStore() authtoken.Store { return &tokenStore{pool: s.pool} }

// opCtx, kısa süreli bir işlem bağlamı üretir (hot-path Verify dahil sınırlı bekleme).
func opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func (t *tokenStore) Create(scope string, ttl time.Duration) (string, string, error) {
	secret, err := authtoken.NewSecret()
	if err != nil {
		return "", "", err
	}
	var expires *time.Time
	if ttl > 0 {
		e := time.Now().UTC().Add(ttl)
		expires = &e
	}
	ctx, cancel := opCtx()
	defer cancel()
	var id string
	err = t.pool.QueryRow(ctx,
		`INSERT INTO tokens (token_hash, scope, expires_at) VALUES ($1, $2, $3) RETURNING id::text`,
		authtoken.HashSecret(secret), scope, expires).Scan(&id)
	if err != nil {
		return "", "", fmt.Errorf("db: token oluşturma: %w", err)
	}
	return id, secret, nil
}

func (t *tokenStore) Verify(scope, presented string) bool {
	if presented == "" {
		return false
	}
	ctx, cancel := opCtx()
	defer cancel()
	// Özet + kapsamla eşleşen, iptal edilmemiş ve süresi dolmamış token'ı ata; son
	// kullanım anını güncelle. Tek UPDATE...RETURNING ile atomik + sabit-zamanlı
	// eşitlik DB'nin hash eşitliğiyle (özet üzerinden, düz sır asla karşılaştırılmaz).
	const q = `
		UPDATE tokens SET last_used_at = now()
		 WHERE token_hash = $1 AND scope = $2 AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now())
	 RETURNING id`
	var id string
	if err := t.pool.QueryRow(ctx, q, authtoken.HashSecret(presented), scope).Scan(&id); err != nil {
		return false
	}
	return true
}

func (t *tokenStore) Revoke(id string) error {
	ctx, cancel := opCtx()
	defer cancel()
	tag, err := t.pool.Exec(ctx,
		`UPDATE tokens SET revoked_at = now() WHERE id = $1::uuid AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("db: token iptal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return authtoken.ErrNotFound
	}
	return nil
}

func (t *tokenStore) List(scope string) ([]authtoken.Token, error) {
	ctx, cancel := opCtx()
	defer cancel()
	q := `SELECT id::text, scope, created_at, expires_at, revoked_at, last_used_at FROM tokens`
	args := []any{}
	if scope != "" {
		q += ` WHERE scope = $1`
		args = append(args, scope)
	}
	q += ` ORDER BY created_at DESC`
	rows, err := t.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("db: token listesi: %w", err)
	}
	defer rows.Close()
	var out []authtoken.Token
	for rows.Next() {
		var tok authtoken.Token
		if err := rows.Scan(&tok.ID, &tok.Scope, &tok.CreatedAt, &tok.ExpiresAt, &tok.RevokedAt, &tok.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
	return out, rows.Err()
}
