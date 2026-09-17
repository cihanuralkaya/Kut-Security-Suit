package db

import (
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"kut.corp/suite/server/internal/casemgmt"
)

// casestore.go — SOC vaka yönetimi için KALICI (PostgreSQL) casemgmt.Store.
// Durum makinesi + append-only zaman çizelgesi mantığının TAMAMINI bellek-içi
// casemgmt.MemStore'a devreder (tek doğruluk kaynağı — mantık ÇOĞALTILMAZ) ve her
// mutasyonun SONUCUNU `cases` tablosuna yazar (write-through). Açılışta DB'den
// yeniden canlandırır (rehydrate).
//
// NOT: okumalar bellekten sunulur → TEK-ÖRNEK tutarlıdır. Çok-örnekli (cluster)
// dağıtımda örnekler arası senkron gerektiğinde saf-DB bir gerçekleştirim ileri bir
// fazdır (SCIM deseni). Kalıcılık (restart'a dayanıklılık) tek örnekte tamdır.
type caseStore struct {
	mem  *casemgmt.MemStore
	pool *pgxpool.Pool
}

// CaseStore, DB destekli bir SOC vaka deposu döner ve mevcut vakaları DB'den
// belleğe yeniden canlandırır.
func (s *Store) CaseStore() casemgmt.Store {
	cs := &caseStore{mem: casemgmt.NewMemStore(), pool: s.pool}
	cs.rehydrate()
	return cs
}

// rehydrate, `cases` tablosundaki tüm vakaları belleğe AYNEN yükler (best-effort;
// hata olursa boş başlar).
func (cs *caseStore) rehydrate() {
	ctx, cancel := opCtx()
	defer cancel()
	rows, err := cs.pool.Query(ctx, `SELECT doc FROM cases`)
	if err != nil {
		return
	}
	defer rows.Close()
	var loaded []casemgmt.Case
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var c casemgmt.Case
		if json.Unmarshal(raw, &c) == nil {
			loaded = append(loaded, c)
		}
	}
	cs.mem.Restore(loaded)
}

// upsert, bir vakanın güncel halini DB'ye yazar (write-through). Mantık zaten
// bellekte uygulanmıştır; bu yalnız kalıcılıktır.
func (cs *caseStore) upsert(c casemgmt.Case) error {
	doc, err := json.Marshal(c)
	if err != nil {
		return err
	}
	ctx, cancel := opCtx()
	defer cancel()
	const q = `INSERT INTO cases (id, tenant_id, status, severity, owner, title, doc, created_at, updated_at)
	           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	           ON CONFLICT (tenant_id, id) DO UPDATE
	             SET status=$3, severity=$4, owner=$5, title=$6, doc=$7, updated_at=$9`
	_, err = cs.pool.Exec(ctx, q, c.ID, c.TenantID, string(c.Status), string(c.Severity), c.Owner, c.Title, doc, c.CreatedAt, c.UpdatedAt)
	return err
}

// Create, vakayı bellekte oluşturur (doğrulama + ilk zaman çizelgesi) ve kalıcılaştırır.
func (cs *caseStore) Create(c casemgmt.Case) (casemgmt.Case, error) {
	created, err := cs.mem.Create(c)
	if err != nil {
		return casemgmt.Case{}, err
	}
	if err := cs.upsert(created); err != nil {
		return casemgmt.Case{}, err
	}
	return created, nil
}

// Get ve List, bellekten sunulur (write-through önbellek).
func (cs *caseStore) Get(tenantID, id string) (casemgmt.Case, error) { return cs.mem.Get(tenantID, id) }
func (cs *caseStore) List(tenantID string) ([]casemgmt.Case, error)  { return cs.mem.List(tenantID) }

// Transition, geçişi bellekte uygular (fail-closed doğrulama) ve kalıcılaştırır.
func (cs *caseStore) Transition(tenantID, id, actor string, to casemgmt.Status, note string) (casemgmt.Case, error) {
	c, err := cs.mem.Transition(tenantID, id, actor, to, note)
	if err != nil {
		return casemgmt.Case{}, err
	}
	return c, cs.upsert(c)
}

// AddEvent, değişmez bir zaman çizelgesi girdisi ekler ve kalıcılaştırır.
func (cs *caseStore) AddEvent(tenantID, id string, ev casemgmt.CaseEvent) (casemgmt.Case, error) {
	c, err := cs.mem.AddEvent(tenantID, id, ev)
	if err != nil {
		return casemgmt.Case{}, err
	}
	return c, cs.upsert(c)
}

// Assign, vaka sahibini değiştirir ve kalıcılaştırır.
func (cs *caseStore) Assign(tenantID, id, actor, owner string) (casemgmt.Case, error) {
	c, err := cs.mem.Assign(tenantID, id, actor, owner)
	if err != nil {
		return casemgmt.Case{}, err
	}
	return c, cs.upsert(c)
}

// Attach, bir referans (asset/user/mitre/evidence) ekler ve kalıcılaştırır.
func (cs *caseStore) Attach(tenantID, id, actor string, kind casemgmt.AttachKind, ref string) (casemgmt.Case, error) {
	c, err := cs.mem.Attach(tenantID, id, actor, kind, ref)
	if err != nil {
		return casemgmt.Case{}, err
	}
	return c, cs.upsert(c)
}
