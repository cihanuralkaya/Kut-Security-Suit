package db

import (
	"strings"
	"testing"
)

// DB gerektirmez: schema.sql'deki yükseltme blokları çıkarılabilir ve beklenen ifadeleri içerir
// (PG testi TestPGUpgradeBlockIdempotent bu bloğu gerçek veritabanında koşturur).
func TestUpgradeBlocksExtractFromSchema(t *testing.T) {
	b1 := strings.Join(upgradeBlock(t, "TENANT-MAC-UPGRADE"), ";\n")
	for _, want := range []string{"CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_tenant_mac",
		"DROP CONSTRAINT IF EXISTS devices_mac_address_bidx_key", "ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id"} {
		if !strings.Contains(b1, want) {
			t.Errorf("TENANT-MAC bloğunda %q yok", want)
		}
	}
	b2 := strings.Join(upgradeBlock(t, "INGEST-TOKEN-TENANT-UPGRADE"), ";\n")
	if !strings.Contains(b2, "ALTER TABLE tokens ADD COLUMN IF NOT EXISTS tenant_id") {
		t.Errorf("INGEST-TOKEN-TENANT bloğunda tokens.tenant_id yok: %s", b2)
	}
	// Yeni indeks, eski kısıttan ÖNCE oluşturulur (sıra güvenliği).
	if strings.Index(b1, "CREATE UNIQUE INDEX") > strings.Index(b1, "DROP CONSTRAINT") {
		t.Error("yeni indeks eski kısıt düşürülmeden ÖNCE oluşturulmalı")
	}
}
