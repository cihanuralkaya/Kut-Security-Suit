package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"kut.corp/suite/server/internal/iam"
)

// scim.go — SCIM 2.0 kullanıcı sağlama için KALICI (PostgreSQL) iam.Provisioner
// gerçekleştirimi (§35). Kullanıcı, çekirdek sorgulanabilir sütunlar + tam kaynağı
// tutan `doc` JSONB olarak scim_users tablosunda saklanır. Deactivate soft-delete'tir.

// scimStore, pgx havuzu üzerinden iam.Provisioner'ı karşılar.
type scimStore struct{ pool *pgxpool.Pool }

// SCIMProvisioner, DB destekli bir SCIM sağlayıcısı döner (kurumsal IAM kalıcılığı).
func (s *Store) SCIMProvisioner() iam.Provisioner { return &scimStore{pool: s.pool} }

// normalizeSCIM, MemProvisioner ile aynı normalizasyonu uygular (şema + meta türü).
func normalizeSCIM(u iam.User) iam.User {
	if len(u.Schemas) == 0 {
		u.Schemas = []string{iam.SchemaUser}
	}
	u.Meta.ResourceType = iam.ResourceTypeUser
	return u
}

// isUniqueViolation, bir hatanın PostgreSQL tekil-kısıt ihlali (23505) olup olmadığını döner.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Create, verilen KİRACIDA yeni bir SCIM kullanıcısı sağlar (id çağıran tarafından
// atanır). Aynı kiracıda id ya da userName çakışırsa ErrUserExists — DB'deki
// UNIQUE(tenant_id, user_name) kısıtı iki kiracının aynı userName'i kullanmasına izin
// verir ama aynı kiracıda tekrarı engeller.
func (p *scimStore) Create(tenantID string, u iam.User) (iam.User, error) {
	if u.ID == "" {
		return iam.User{}, errors.New("db: SCIM kullanıcısı id gerektirir")
	}
	tid := iam.NormTenant(tenantID)
	t := time.Now().UTC()
	u = normalizeSCIM(u)
	u.Meta.Created = t
	u.Meta.LastModified = t
	doc, err := json.Marshal(u)
	if err != nil {
		return iam.User{}, err
	}
	const q = `INSERT INTO scim_users (id, tenant_id, user_name, external_id, active, doc)
	           VALUES ($1::uuid, $2, $3, NULLIF($4,''), $5, $6)`
	if _, err := p.pool.Exec(context.Background(), q, u.ID, tid, u.UserName, u.ExternalID, u.Active, doc); err != nil {
		if isUniqueViolation(err) {
			return iam.User{}, iam.ErrUserExists
		}
		return iam.User{}, err
	}
	return u, nil
}

// Get, kiracı+id'deki kullanıcıyı döner. Yoksa (ya da başka kiracıya aitse) ErrUserNotFound.
func (p *scimStore) Get(tenantID, id string) (iam.User, error) {
	const q = `SELECT doc FROM scim_users WHERE id = $1::uuid AND tenant_id = $2`
	var raw []byte
	if err := p.pool.QueryRow(context.Background(), q, id, iam.NormTenant(tenantID)).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.User{}, iam.ErrUserNotFound
		}
		return iam.User{}, err
	}
	var u iam.User
	if err := json.Unmarshal(raw, &u); err != nil {
		return iam.User{}, err
	}
	return u, nil
}

// Replace, kiracı+id'deki kullanıcıyı tümüyle değiştirir (SCIM PUT). Yoksa ErrUserNotFound.
func (p *scimStore) Replace(tenantID, id string, u iam.User) (iam.User, error) {
	tid := iam.NormTenant(tenantID)
	existing, err := p.Get(tid, id)
	if err != nil {
		return iam.User{}, err
	}
	u.ID = id
	u = normalizeSCIM(u)
	u.Meta.Created = existing.Meta.Created // oluşturma anı korunur
	u.Meta.LastModified = time.Now().UTC()
	doc, err := json.Marshal(u)
	if err != nil {
		return iam.User{}, err
	}
	const q = `UPDATE scim_users
	              SET user_name = $3, external_id = NULLIF($4,''), active = $5, doc = $6, updated_at = now()
	            WHERE id = $1::uuid AND tenant_id = $2`
	if _, err := p.pool.Exec(context.Background(), q, id, tid, u.UserName, u.ExternalID, u.Active, doc); err != nil {
		if isUniqueViolation(err) {
			return iam.User{}, iam.ErrUserExists
		}
		return iam.User{}, err
	}
	return u, nil
}

// Deactivate, kiracı+id'deki kullanıcıyı active=false yapar (soft-delete).
func (p *scimStore) Deactivate(tenantID, id string) (iam.User, error) {
	tid := iam.NormTenant(tenantID)
	u, err := p.Get(tid, id)
	if err != nil {
		return iam.User{}, err
	}
	u.Active = false
	u.Meta.LastModified = time.Now().UTC()
	doc, err := json.Marshal(u)
	if err != nil {
		return iam.User{}, err
	}
	const q = `UPDATE scim_users SET active = FALSE, doc = $3, updated_at = now() WHERE id = $1::uuid AND tenant_id = $2`
	if _, err := p.pool.Exec(context.Background(), q, id, tid, doc); err != nil {
		return iam.User{}, err
	}
	return u, nil
}
