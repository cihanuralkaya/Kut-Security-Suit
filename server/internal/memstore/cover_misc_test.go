package memstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/evidence"
)

// OpenIncident + BumpIncident + ListIncidents: incident açma, sayaç yükseltme,
// son-görülmeye göre sıralı listeleme.
func TestIncidentLifecycle(t *testing.T) {
	ctx := context.Background()
	s := New()
	t0 := time.Now()

	id1, err := s.OpenIncident(ctx, "dev-1", "key-1", "rule-A", "T1059", "HIGH", "şüpheli süreç", t0)
	if err != nil {
		t.Fatal(err)
	}
	if id1 == "" {
		t.Fatal("incident id atanmalıydı")
	}
	id2, _ := s.OpenIncident(ctx, "dev-2", "key-2", "rule-B", "T1055", "LOW", "enjeksiyon", t0.Add(time.Second))

	// id1'i bump et → count artar, lastSeen en yeni olur.
	if err := s.BumpIncident(ctx, id1, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	// Bilinmeyen id bump no-op.
	if err := s.BumpIncident(ctx, "yok", t0); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListIncidents(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("2 incident beklenirdi: %d", len(list))
	}
	// lastSeen DESC: id1 (bump ile en yeni) ilk sırada.
	if list[0].ID != id1 {
		t.Fatalf("son-görülmeye göre id1 ilk olmalıydı: %+v", list[0])
	}
	if list[0].Count != 2 {
		t.Fatalf("id1 sayacı 2 olmalıydı: %d", list[0].Count)
	}
	if list[0].Status != "OPEN" {
		t.Fatalf("yeni incident OPEN olmalıydı: %q", list[0].Status)
	}
	if list[1].ID != id2 {
		t.Fatalf("ikinci sırada id2 beklenirdi: %+v", list[1])
	}

	// limit.
	lim, _ := s.ListIncidents(ctx, 1)
	if len(lim) != 1 {
		t.Fatalf("limit=1 uygulanmalıydı: %d", len(lim))
	}
}

// SavePendingWipe + GetPendingWipe + ListPendingWipes + DeletePendingWipe.
func TestPendingWipeCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()
	adminID := s.SeedAdmin("req@x", "h", "ADMIN")

	// Yokken Get → false.
	if _, ok, _ := s.GetPendingWipe(ctx, "dev-1"); ok {
		t.Fatal("kayıt yokken ok=false olmalıydı")
	}

	if err := s.SavePendingWipe(ctx, "dev-1", adminID, "kayıp cihaz"); err != nil {
		t.Fatal(err)
	}
	by, ok, err := s.GetPendingWipe(ctx, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || by != adminID {
		t.Fatalf("bekleyen wipe requestedBy hatalı: ok=%v by=%q", ok, by)
	}

	// ListPendingWipes: requestedBy e-postaya çözülür.
	rows, _ := s.ListPendingWipes(ctx)
	if len(rows) != 1 {
		t.Fatalf("1 bekleyen wipe beklenirdi: %d", len(rows))
	}
	if rows[0].RequestedBy != "req@x" || rows[0].Reason != "kayıp cihaz" || rows[0].DeviceID != "dev-1" {
		t.Fatalf("bekleyen wipe satırı hatalı: %+v", rows[0])
	}

	// Delete.
	if err := s.DeletePendingWipe(ctx, "dev-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetPendingWipe(ctx, "dev-1"); ok {
		t.Fatal("silmeden sonra kayıt olmamalıydı")
	}
}

// SaveSearch + ListSavedSearches + DeleteSavedSearch + toSavedSearchRow:
// createdBy e-postaya çözülür, liste en yeniden eskiye.
func TestSavedSearches(t *testing.T) {
	ctx := context.Background()
	s := New()
	adminID := s.SeedAdmin("hunter@x", "h", "OPERATOR")

	r1, err := s.SaveSearch(ctx, "brute-force", `{"severity":"HIGH"}`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	if r1.CreatedBy != "hunter@x" {
		t.Fatalf("createdBy e-postaya çözülmeliydi: %q", r1.CreatedBy)
	}
	if r1.Name != "brute-force" || r1.Filter != `{"severity":"HIGH"}` {
		t.Fatalf("kayıtlı arama alanları hatalı: %+v", r1)
	}
	time.Sleep(time.Millisecond)
	r2, _ := s.SaveSearch(ctx, "exfil", `{"category":"NETWORK"}`, adminID)

	list, err := s.ListSavedSearches(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("2 kayıtlı arama beklenirdi: %d", len(list))
	}
	// En yeniden eskiye: r2 ilk.
	if list[0].ID != r2.ID {
		t.Fatalf("en yeni arama ilk sırada olmalıydı: %+v", list[0])
	}

	// Sahiplik: BAŞKA bir owner ile silme no-op olmalı (IDOR önlemi) → deleted=false.
	if ok, err := s.DeleteSavedSearch(ctx, r1.ID, "baska-admin"); err != nil || ok {
		t.Fatalf("yanlış owner silme false dönmeli: ok=%v err=%v", ok, err)
	}
	if list, _ := s.ListSavedSearches(ctx); len(list) != 2 {
		t.Fatalf("yanlış owner ile silme yapılmamalıydı, hâlâ 2 olmalı: %d", len(list))
	}

	// Delete r1 (doğru owner) → deleted=true.
	if ok, err := s.DeleteSavedSearch(ctx, r1.ID, adminID); err != nil || !ok {
		t.Fatalf("doğru owner silme true dönmeli: ok=%v err=%v", ok, err)
	}
	list, _ = s.ListSavedSearches(ctx)
	if len(list) != 1 || list[0].ID != r2.ID {
		t.Fatalf("silmeden sonra yalnız r2 kalmalıydı: %+v", list)
	}

	// Bilinmeyen id silme no-op → deleted=false.
	if ok, err := s.DeleteSavedSearch(ctx, "yok", adminID); err != nil || ok {
		t.Fatalf("bilinmeyen id false/no-op olmalı: ok=%v err=%v", ok, err)
	}

	// toSavedSearchRow: adminsByID eşleşmezse createdBy ham id kalır.
	row := toSavedSearchRow(savedSearchRec{id: "x", name: "n", filter: "f", createdBy: "unknown-id"}, s.adminsByID)
	if row.CreatedBy != "unknown-id" {
		t.Fatalf("eşleşmeyen createdBy ham kalmalıydı: %q", row.CreatedBy)
	}
}

// SaveArtifact + ListArtifacts + GetArtifact + PurgeArtifactsOlderThan: artefakt
// yaşam-döngüsü; ListArtifacts içerik taşımaz, GetArtifact içerik döner.
func TestArtifactLifecycle(t *testing.T) {
	ctx := context.Background()
	s := New()

	content := []byte("dump-bytes")
	id, err := s.SaveArtifact(ctx, "dev-1", "cmd-1", "/tmp/x.bin", "abc123", content)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("artefakt id atanmalıydı")
	}
	// Kaynağı değiştir: depodaki kopya etkilenmemeli.
	content[0] = 'X'

	rows, err := s.ListArtifacts(ctx, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("1 artefakt beklenirdi: %d", len(rows))
	}
	if rows[0].Size != len("dump-bytes") || rows[0].Path != "/tmp/x.bin" || rows[0].SHA256 != "abc123" {
		t.Fatalf("artefakt meta hatalı: %+v", rows[0])
	}

	// GetArtifact içerik döner (kopya, orijinal mutasyondan etkilenmez).
	ac, ok, err := s.GetArtifact(ctx, id)
	if err != nil || !ok {
		t.Fatalf("GetArtifact başarısız: ok=%v err=%v", ok, err)
	}
	if string(ac.Content) != "dump-bytes" {
		t.Fatalf("artefakt içeriği bozulmamalıydı: %q", ac.Content)
	}

	// Bilinmeyen id.
	if _, ok, _ := s.GetArtifact(ctx, "yok"); ok {
		t.Fatal("bilinmeyen artefakt ok=false olmalıydı")
	}
	// Başka cihaz listesi boş.
	if other, _ := s.ListArtifacts(ctx, "dev-2"); len(other) != 0 {
		t.Fatalf("başka cihazda artefakt olmamalıydı: %d", len(other))
	}

	// PurgeArtifactsOlderThan: gelecekteki cutoff → hepsini düşürür.
	removed, err := s.PurgeArtifactsOlderThan(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("1 artefakt purge edilmeliydi: %d", removed)
	}
	if rows, _ := s.ListArtifacts(ctx, "dev-1"); len(rows) != 0 {
		t.Fatalf("purge sonrası artefakt kalmamalıydı: %d", len(rows))
	}
}

// AppendCustody + ListCustody: ekle-yalnız gözetim zinciri; çift seq hata döner.
func TestCustodyChain(t *testing.T) {
	ctx := context.Background()
	s := New()

	// Boşken liste boş.
	if c, _ := s.ListCustody(ctx, "ev-1"); len(c) != 0 {
		t.Fatalf("boş gözetim beklenirdi: %d", len(c))
	}

	e1 := evidence.CustodyEntry{Seq: 1, Actor: "a@x", Action: "COLLECT", At: time.Now()}
	e2 := evidence.CustodyEntry{Seq: 2, Actor: "b@x", Action: "TRANSFER", At: time.Now()}
	if err := s.AppendCustody(ctx, "ev-1", e1); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCustody(ctx, "ev-1", e2); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListCustody(ctx, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("gözetim zinciri hatalı: %+v", got)
	}

	// Çift seq → hata (UNIQUE(evidence_id, seq) taklidi).
	err = s.AppendCustody(ctx, "ev-1", evidence.CustodyEntry{Seq: 1, Actor: "c@x"})
	if err == nil || !strings.Contains(err.Error(), "seq") {
		t.Fatalf("çift seq hata dönmeliydi: %v", err)
	}
}

// MSP müşteri yaşam-döngüsü: Add/List/Get/Deactivate.
func TestMSPCustomers(t *testing.T) {
	s := New()

	c1, err := s.MSPAddCustomer("Acme", "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if c1.ID == "" || !c1.Active || c1.Name != "Acme" {
		t.Fatalf("müşteri kaydı hatalı: %+v", c1)
	}
	time.Sleep(time.Millisecond)
	c2, _ := s.MSPAddCustomer("Globex", "tenant-2")

	// List en yeniden eskiye.
	list, err := s.MSPListCustomers()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != c2.ID {
		t.Fatalf("müşteri listesi en yeniden eskiye olmalıydı: %+v", list)
	}

	// Get.
	got, ok, err := s.MSPGetCustomer(c1.ID)
	if err != nil || !ok || got.Name != "Acme" {
		t.Fatalf("MSPGetCustomer hatalı: ok=%v got=%+v err=%v", ok, got, err)
	}
	if _, ok, _ := s.MSPGetCustomer("yok"); ok {
		t.Fatal("bilinmeyen müşteri ok=false olmalıydı")
	}

	// Deactivate.
	ok, err = s.MSPDeactivateCustomer(c1.ID)
	if err != nil || !ok {
		t.Fatalf("deaktivasyon başarılı olmalıydı: ok=%v err=%v", ok, err)
	}
	got, _, _ = s.MSPGetCustomer(c1.ID)
	if got.Active {
		t.Fatal("müşteri pasifleştirilmeliydi")
	}
	// Zaten pasif / bilinmeyen → false.
	if ok, _ := s.MSPDeactivateCustomer(c1.ID); ok {
		t.Fatal("zaten pasif müşteri false dönmeliydi")
	}
	if ok, _ := s.MSPDeactivateCustomer("yok"); ok {
		t.Fatal("bilinmeyen müşteri false dönmeliydi")
	}
}

// WriteAudit + ListAudit: denetim kaydı yazılır, en yeniden eskiye listelenir,
// adminID e-postaya çözülür, limit uygulanır.
func TestAuditWriteAndList(t *testing.T) {
	ctx := context.Background()
	s := New()
	adminID := s.SeedAdmin("auditor@x", "h", "ADMIN")

	if err := s.WriteAudit(ctx, adminID, "LOGIN", "session", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAudit(ctx, adminID, "ASSIGN_POLICY", "device", "d1"); err != nil {
		t.Fatal(err)
	}
	// Bilinmeyen admin → e-posta boş kalır.
	if err := s.WriteAudit(ctx, "unknown-admin", "SYSTEM", "x", "y"); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ListAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("3 denetim kaydı beklenirdi: %d", len(rows))
	}
	// En yeniden eskiye: son yazılan (SYSTEM) ilk sırada.
	if rows[0].Action != "SYSTEM" {
		t.Fatalf("en yeni kayıt ilk sırada olmalıydı: %q", rows[0].Action)
	}
	if rows[0].AdminEmail != "" {
		t.Fatalf("bilinmeyen admin e-postası boş kalmalıydı: %q", rows[0].AdminEmail)
	}
	if rows[2].AdminEmail != "auditor@x" {
		t.Fatalf("adminID e-postaya çözülmeliydi: %q", rows[2].AdminEmail)
	}

	// Zincir tutarlı olmalı.
	if err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("denetim zinciri geçerli olmalıydı: %v", err)
	}

	// limit.
	lim, _ := s.ListAudit(ctx, 1)
	if len(lim) != 1 {
		t.Fatalf("limit=1 uygulanmalıydı: %d", len(lim))
	}
}

// randID: prefix'i korur, benzersizdir ve prefix+16 hex uzunluğundadır.
func TestRandID(t *testing.T) {
	a := randID("dev-")
	b := randID("dev-")
	if !strings.HasPrefix(a, "dev-") {
		t.Fatalf("prefix korunmalıydı: %q", a)
	}
	if a == b {
		t.Fatalf("randID benzersiz olmalıydı: %q == %q", a, b)
	}
	if len(a) != len("dev-")+16 {
		t.Fatalf("randID uzunluğu prefix+16 hex olmalıydı: %q (len=%d)", a, len(a))
	}
}

// LatestUpdate: bellek-içi depo OTA sürümü tutmaz → nil, nil.
func TestLatestUpdateNil(t *testing.T) {
	s := New()
	m, err := s.LatestUpdate(context.Background(), "windows", "amd64", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		t.Fatalf("LatestUpdate nil dönmeliydi: %+v", m)
	}
}

// Ping: bellek-içi depo her zaman sağlıklı.
func TestPing(t *testing.T) {
	s := New()
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping nil dönmeliydi: %v", err)
	}
}
