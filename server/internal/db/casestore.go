package db

import (
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"kut.corp/suite/server/internal/casemgmt"
)

// casestore.go — SOC vaka yönetimi için CLUSTER-SAFE (PostgreSQL) casemgmt.Store.
// Okumalar (Get/List) DOĞRUDAN DB'den sunulur → çok-örnekli (cluster) dağıtımda tüm
// örnekler tutarlıdır (bellek-önbelleği yok; bir örneğin yazdığını diğeri hemen görür).
// Mutasyonlar tek transaction'da `SELECT ... FOR UPDATE` row-lock ile atomiktir: iki
// eşzamanlı örnek aynı vakayı güncellese bile lost-update olmaz. Durum-makinesi +
// append-only zaman-çizelgesi mantığı ÇOĞALTILMAZ — her mutasyon, kilitli satırın güncel
// Case'ini tek-vaka bellek deposuna yükleyip casemgmt mantığını yeniden kullanır.
type caseStore struct {
	pool *pgxpool.Pool
}

// CaseStore, cluster-safe DB destekli bir SOC vaka deposu döner.
func (s *Store) CaseStore() casemgmt.Store { return &caseStore{pool: s.pool} }

// scanDoc, bir `doc` JSONB satırını Case'e çözer.
func scanDoc(raw []byte) (casemgmt.Case, error) {
	var c casemgmt.Case
	if err := json.Unmarshal(raw, &c); err != nil {
		return casemgmt.Case{}, err
	}
	return c, nil
}

// Get, vakayı DOĞRUDAN DB'den okur (cluster-tutarlı). Yoksa ErrCaseNotFound.
func (cs *caseStore) Get(tenantID, id string) (casemgmt.Case, error) {
	ctx, cancel := opCtx()
	defer cancel()
	var raw []byte
	err := cs.pool.QueryRow(ctx, `SELECT doc FROM cases WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return casemgmt.Case{}, casemgmt.ErrCaseNotFound
	}
	if err != nil {
		return casemgmt.Case{}, err
	}
	return scanDoc(raw)
}

// List, kiracının tüm vakalarını DOĞRUDAN DB'den CreatedAt sırasıyla okur.
func (cs *caseStore) List(tenantID string) ([]casemgmt.Case, error) {
	ctx, cancel := opCtx()
	defer cancel()
	rows, err := cs.pool.Query(ctx, `SELECT doc FROM cases WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []casemgmt.Case{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		c, err := scanDoc(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Create, vakayı casemgmt mantığıyla doğrular (ilk timeline) ve ATOMİK ekler. Eşzamanlı
// çift-oluşturmayı DB çözer (ON CONFLICT DO NOTHING → hiç satır etkilenmezse ErrCaseExists).
func (cs *caseStore) Create(c casemgmt.Case) (casemgmt.Case, error) {
	tmp := casemgmt.NewMemStore()
	created, err := tmp.Create(c)
	if err != nil {
		return casemgmt.Case{}, err
	}
	doc, err := json.Marshal(created)
	if err != nil {
		return casemgmt.Case{}, err
	}
	ctx, cancel := opCtx()
	defer cancel()
	const q = `INSERT INTO cases (id, tenant_id, status, severity, owner, title, doc, created_at, updated_at)
	           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (tenant_id, id) DO NOTHING`
	tag, err := cs.pool.Exec(ctx, q, created.ID, created.TenantID, string(created.Status), string(created.Severity),
		created.Owner, created.Title, doc, created.CreatedAt, created.UpdatedAt)
	if err != nil {
		return casemgmt.Case{}, err
	}
	if tag.RowsAffected() == 0 {
		return casemgmt.Case{}, casemgmt.ErrCaseExists
	}
	return created, nil
}

// mutate, kilitli satırın güncel Case'ine casemgmt mantığını uygular (tek atomik tx):
// SELECT ... FOR UPDATE → tek-vaka MemStore → fn → UPDATE → commit. Lost-update yok;
// fn hata dönerse tx geri alınır ve durum DEĞİŞMEZ (fail-closed).
func (cs *caseStore) mutate(tenantID, id string, fn func(*casemgmt.MemStore) (casemgmt.Case, error)) (casemgmt.Case, error) {
	ctx, cancel := opCtx()
	defer cancel()
	tx, err := cs.pool.Begin(ctx)
	if err != nil {
		return casemgmt.Case{}, err
	}
	defer tx.Rollback(ctx)

	var raw []byte
	err = tx.QueryRow(ctx, `SELECT doc FROM cases WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return casemgmt.Case{}, casemgmt.ErrCaseNotFound
	}
	if err != nil {
		return casemgmt.Case{}, err
	}
	cur, err := scanDoc(raw)
	if err != nil {
		return casemgmt.Case{}, err
	}
	tmp := casemgmt.NewMemStore()
	tmp.Restore([]casemgmt.Case{cur})
	updated, err := fn(tmp)
	if err != nil {
		return casemgmt.Case{}, err // geçersiz geçiş vb. → tx rollback (defer), durum korunur
	}
	doc, err := json.Marshal(updated)
	if err != nil {
		return casemgmt.Case{}, err
	}
	const q = `UPDATE cases SET status=$3, severity=$4, owner=$5, title=$6, doc=$7, updated_at=$8
	           WHERE tenant_id=$1 AND id=$2`
	if _, err := tx.Exec(ctx, q, tenantID, id, string(updated.Status), string(updated.Severity),
		updated.Owner, updated.Title, doc, updated.UpdatedAt); err != nil {
		return casemgmt.Case{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return casemgmt.Case{}, err
	}
	return updated, nil
}

// Transition, geçişi kilitli satır üzerinde atomik uygular (fail-closed doğrulama).
func (cs *caseStore) Transition(tenantID, id, actor string, to casemgmt.Status, note string) (casemgmt.Case, error) {
	return cs.mutate(tenantID, id, func(m *casemgmt.MemStore) (casemgmt.Case, error) {
		return m.Transition(tenantID, id, actor, to, note)
	})
}

// AddEvent, değişmez bir zaman-çizelgesi girdisini atomik ekler.
func (cs *caseStore) AddEvent(tenantID, id string, ev casemgmt.CaseEvent) (casemgmt.Case, error) {
	return cs.mutate(tenantID, id, func(m *casemgmt.MemStore) (casemgmt.Case, error) {
		return m.AddEvent(tenantID, id, ev)
	})
}

// Assign, vaka sahibini atomik değiştirir.
func (cs *caseStore) Assign(tenantID, id, actor, owner string) (casemgmt.Case, error) {
	return cs.mutate(tenantID, id, func(m *casemgmt.MemStore) (casemgmt.Case, error) {
		return m.Assign(tenantID, id, actor, owner)
	})
}

// Attach, bir referans (asset/user/mitre/evidence) atomik ekler.
func (cs *caseStore) Attach(tenantID, id, actor string, kind casemgmt.AttachKind, ref string) (casemgmt.Case, error) {
	return cs.mutate(tenantID, id, func(m *casemgmt.MemStore) (casemgmt.Case, error) {
		return m.Attach(tenantID, id, actor, kind, ref)
	})
}
