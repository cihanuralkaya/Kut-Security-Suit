package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"kut.corp/suite/server/internal/msp"
)

// msp.go — MSP müşteri kaydı için KALICI (PostgreSQL) depo (§37). Müşteriler
// msp_customers tablosunda saklanır; Deactivate soft-delete'tir. Kullanım/faturalama
// ölçümü ayrıca çalışma-zamanı sayaçlarıdır (msp.UsageMeter, kalıcı değil).

// MSPAddCustomer, yeni bir MSP müşterisi ekler ve oluşturulan kaydı döner.
func (s *Store) MSPAddCustomer(name, tenantID string) (msp.Customer, error) {
	const q = `
		INSERT INTO msp_customers (name, tenant_id)
		VALUES ($1, $2)
		RETURNING id::text, name, tenant_id, active, created_at`
	var c msp.Customer
	if err := s.pool.QueryRow(context.Background(), q, name, tenantID).
		Scan(&c.ID, &c.Name, &c.TenantID, &c.Active, &c.CreatedAt); err != nil {
		return msp.Customer{}, fmt.Errorf("db: msp müşteri ekleme: %w", err)
	}
	return c, nil
}

// MSPListCustomers, tüm MSP müşterilerini (en yeniden eskiye) döner.
func (s *Store) MSPListCustomers() ([]msp.Customer, error) {
	const q = `SELECT id::text, name, tenant_id, active, created_at FROM msp_customers ORDER BY created_at DESC`
	rows, err := s.pool.Query(context.Background(), q)
	if err != nil {
		return nil, fmt.Errorf("db: msp müşteri listesi: %w", err)
	}
	defer rows.Close()
	var out []msp.Customer
	for rows.Next() {
		var c msp.Customer
		if err := rows.Scan(&c.ID, &c.Name, &c.TenantID, &c.Active, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: msp müşteri okuma: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MSPGetCustomer, kimliğe göre müşteriyi döner (yoksa ok=false).
func (s *Store) MSPGetCustomer(id string) (msp.Customer, bool, error) {
	const q = `SELECT id::text, name, tenant_id, active, created_at FROM msp_customers WHERE id = $1::uuid`
	var c msp.Customer
	err := s.pool.QueryRow(context.Background(), q, id).Scan(&c.ID, &c.Name, &c.TenantID, &c.Active, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return msp.Customer{}, false, nil
		}
		return msp.Customer{}, false, fmt.Errorf("db: msp müşteri getir: %w", err)
	}
	return c, true, nil
}

// MSPDeactivateCustomer, müşteriyi devre dışı bırakır (soft-delete). Bir satır
// güncellendiyse true döner (yoksa/zaten pasifse false).
func (s *Store) MSPDeactivateCustomer(id string) (bool, error) {
	const q = `UPDATE msp_customers SET active = FALSE WHERE id = $1::uuid AND active = TRUE`
	tag, err := s.pool.Exec(context.Background(), q, id)
	if err != nil {
		return false, fmt.Errorf("db: msp müşteri devre dışı: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
