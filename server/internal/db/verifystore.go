package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"kut.corp/suite/server/internal/verify"
)

// verifystore.go — Remediation Verification için CLUSTER-SAFE (PostgreSQL) verify.Store.
// casestore.go ile aynı ilke: okumalar (Get/List/ListAll/GetAny) DOĞRUDAN DB'den sunulur
// (bellek-önbelleği yok → çok-örnekli dağıtımda tutarlı); mutasyon (Resolve) tek
// transaction'da `SELECT ... FOR UPDATE` row-lock ile atomiktir. Normalizasyon mantığı
// (Baseline türetme, PENDING varsayılanı, OpenedAt) ÇOĞALTILMAZ — Open, tek-check bellek
// deposuna verify.MemStore mantığını uygulayıp sonucu upsert eder.
type verifyStore struct {
	pool *pgxpool.Pool
}

// VerifyStore, cluster-safe DB destekli bir remediation-doğrulama deposu döner.
func (s *Store) VerifyStore() verify.Store { return &verifyStore{pool: s.pool} }

// scanVCheck, bir `doc` JSONB satırını verify.Check'e çözer.
func scanVCheck(raw []byte) (verify.Check, error) {
	var c verify.Check
	if err := json.Unmarshal(raw, &c); err != nil {
		return verify.Check{}, err
	}
	return c, nil
}

// Open, check'i verify.MemStore mantığıyla normalize eder (Baseline/OpenedAt/PENDING) ve
// ATOMİK upsert eder. MemStore.Open aynı anahtarda üzerine yazdığından burada da
// ON CONFLICT DO UPDATE (aynı semantik). id/tenant boşsa MemStore hatası döner.
func (vs *verifyStore) Open(c verify.Check) (verify.Check, error) {
	tmp := verify.NewMemStore()
	norm, err := tmp.Open(c)
	if err != nil {
		return verify.Check{}, err
	}
	doc, err := json.Marshal(norm)
	if err != nil {
		return verify.Check{}, err
	}
	ctx, cancel := opCtx()
	defer cancel()
	const q = `INSERT INTO verify_checks (id, tenant_id, device_id, rule_id, kind, outcome, doc, opened_at)
	           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	           ON CONFLICT (tenant_id, id) DO UPDATE SET
	             device_id=EXCLUDED.device_id, rule_id=EXCLUDED.rule_id, kind=EXCLUDED.kind,
	             outcome=EXCLUDED.outcome, doc=EXCLUDED.doc, opened_at=EXCLUDED.opened_at`
	if _, err := vs.pool.Exec(ctx, q, norm.ID, norm.TenantID, norm.DeviceID, norm.RuleID,
		string(norm.Kind), string(norm.Outcome), doc, norm.OpenedAt); err != nil {
		return verify.Check{}, err
	}
	return norm, nil
}

// Get, check'i DOĞRUDAN DB'den okur (cluster-tutarlı, kiracı-kapsamlı). Boş kiracı →
// ErrTenantRequired; bulunamaz/kiracı eşleşmez → ErrCheckNotFound (varlık sızmaz).
func (vs *verifyStore) Get(tenantID, id string) (verify.Check, error) {
	if tenantID == "" {
		return verify.Check{}, verify.ErrTenantRequired
	}
	ctx, cancel := opCtx()
	defer cancel()
	var raw []byte
	err := vs.pool.QueryRow(ctx, `SELECT doc FROM verify_checks WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return verify.Check{}, verify.ErrCheckNotFound
	}
	if err != nil {
		return verify.Check{}, err
	}
	return scanVCheck(raw)
}

// List, kiracının tüm check'lerini DOĞRUDAN DB'den OpenedAt sırasıyla okur.
func (vs *verifyStore) List(tenantID string) ([]verify.Check, error) {
	if tenantID == "" {
		return nil, verify.ErrTenantRequired
	}
	ctx, cancel := opCtx()
	defer cancel()
	return vs.queryChecks(ctx, `SELECT doc FROM verify_checks WHERE tenant_id=$1 ORDER BY opened_at, id`, tenantID)
}

// ListAll, TÜM kiracıların check'lerini DOĞRUDAN DB'den okur (platform admini; kiracı
// filtresi YOK). Çağıran katman yalnız kiracısız (platform) admin için çağırmalıdır.
func (vs *verifyStore) ListAll() ([]verify.Check, error) {
	ctx, cancel := opCtx()
	defer cancel()
	return vs.queryChecks(ctx, `SELECT doc FROM verify_checks ORDER BY opened_at, id`)
}

// GetAny, kiracıdan bağımsız id ile tek check okur (platform admini). Yoksa
// ErrCheckNotFound. Çağıran katman yalnız kiracısız (platform) admin için çağırmalıdır.
func (vs *verifyStore) GetAny(id string) (verify.Check, error) {
	ctx, cancel := opCtx()
	defer cancel()
	var raw []byte
	err := vs.pool.QueryRow(ctx, `SELECT doc FROM verify_checks WHERE id=$1 ORDER BY opened_at LIMIT 1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return verify.Check{}, verify.ErrCheckNotFound
	}
	if err != nil {
		return verify.Check{}, err
	}
	return scanVCheck(raw)
}

// Resolve, check'i bir sonuca + kalan riske ATOMİK bağlar (VerifiedAt=now). Kilitli satır
// (SELECT ... FOR UPDATE) verify.MemStore mantığıyla güncellenir → eşzamanlı iki örnek
// lost-update yaşamaz. Bulunamazsa ErrCheckNotFound (tx rollback, durum korunur).
func (vs *verifyStore) Resolve(tenantID, id string, o verify.Outcome, residual int) (verify.Check, error) {
	if tenantID == "" {
		return verify.Check{}, verify.ErrTenantRequired
	}
	ctx, cancel := opCtx()
	defer cancel()
	tx, err := vs.pool.Begin(ctx)
	if err != nil {
		return verify.Check{}, err
	}
	defer tx.Rollback(ctx)

	var raw []byte
	err = tx.QueryRow(ctx, `SELECT doc FROM verify_checks WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return verify.Check{}, verify.ErrCheckNotFound
	}
	if err != nil {
		return verify.Check{}, err
	}
	cur, err := scanVCheck(raw)
	if err != nil {
		return verify.Check{}, err
	}
	tmp := verify.NewMemStore()
	tmp.Restore([]verify.Check{cur})
	updated, err := tmp.Resolve(tenantID, id, o, residual)
	if err != nil {
		return verify.Check{}, err
	}
	doc, err := json.Marshal(updated)
	if err != nil {
		return verify.Check{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE verify_checks SET outcome=$3, doc=$4 WHERE tenant_id=$1 AND id=$2`,
		tenantID, id, string(updated.Outcome), doc); err != nil {
		return verify.Check{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return verify.Check{}, err
	}
	return updated, nil
}

// Restore, DB destekli depoda no-op'tur: kalıcılık zaten DB'nin kendisidir (bellek-içi
// rehydration gerekmez). Arayüz bütünlüğü için var.
func (vs *verifyStore) Restore(_ []verify.Check) {}

// queryChecks, verilen sorguyu koşup satırları verify.Check dilimine çözer (ortak yardımcı).
func (vs *verifyStore) queryChecks(ctx context.Context, q string, args ...any) ([]verify.Check, error) {
	rows, err := vs.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []verify.Check{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		c, err := scanVCheck(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
