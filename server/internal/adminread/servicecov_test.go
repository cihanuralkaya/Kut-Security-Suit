package adminread

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/detect"
)

// richStore, temel memStore fake'ini genişletir: incident / bekleyen-wipe / kayıtlı-arama
// yüzeylerine yapılandırılabilir veri ve seçili metotlara hata enjeksiyonu ekler
// (memStore bunları sabit nil döndürür). Diğer tüm metotlar memStore'dan devralınır.
type richStore struct {
	*memStore
	incidents     []IncidentRow
	pendingWipes  []PendingWipeRow
	savedSearches []SavedSearchRow

	deletedIDs []string
	saveCalls  []SavedSearchRow

	errIncidents error
	errPending   error
	errSaved     error
	errDelete    error
	errDevices   error
	errQuery     error
}

func (r *richStore) ListIncidents(_ context.Context, _ int) ([]IncidentRow, error) {
	return r.incidents, r.errIncidents
}
func (r *richStore) ListPendingWipes(_ context.Context) ([]PendingWipeRow, error) {
	return r.pendingWipes, r.errPending
}
func (r *richStore) ListSavedSearches(_ context.Context) ([]SavedSearchRow, error) {
	return r.savedSearches, r.errSaved
}
func (r *richStore) SaveSearch(_ context.Context, name, filterJSON, createdBy string) (SavedSearchRow, error) {
	row := SavedSearchRow{ID: "srch-new", Name: name, Filter: filterJSON, CreatedBy: createdBy, CreatedAt: time.Now()}
	r.saveCalls = append(r.saveCalls, row)
	return row, nil
}
func (r *richStore) DeleteSavedSearch(_ context.Context, id string) error {
	r.deletedIDs = append(r.deletedIDs, id)
	return r.errDelete
}
func (r *richStore) ListDevices(ctx context.Context, limit int) ([]DeviceRow, error) {
	if r.errDevices != nil {
		return nil, r.errDevices
	}
	return r.memStore.ListDevices(ctx, limit)
}
func (r *richStore) QueryEvents(ctx context.Context, f EventFilter) ([]EventRow, error) {
	if r.errQuery != nil {
		return nil, r.errQuery
	}
	return r.memStore.QueryEvents(ctx, f)
}

func newRich(m *memStore) *richStore {
	if m == nil {
		m = &memStore{}
	}
	return &richStore{memStore: m}
}

// --- Coverage --------------------------------------------------------------

func TestCoverage(t *testing.T) {
	now := time.Now()
	store := &memStore{devices: []DeviceRow{
		{ID: "d1", AgentVersion: "1.2.0", LastSeen: now},                   // online
		{ID: "d2", AgentVersion: "1.2.0", LastSeen: now.Add(-time.Hour)},   // stale
		{ID: "d3", AgentVersion: "1.1.0", LastSeen: now.Add(-time.Minute)}, // stale
		{ID: "d4", AgentVersion: "", LastSeen: now},                        // online, sürüm yok
	}}
	svc := NewService(store, newCipher(t))

	cov, err := svc.Coverage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cov.Total != 4 {
		t.Fatalf("total 4 beklenirdi, %d", cov.Total)
	}
	if cov.Online != 2 || cov.Stale != 2 {
		t.Fatalf("online/stale 2/2 beklenirdi, %d/%d", cov.Online, cov.Stale)
	}
	if cov.CoveragePct != 50 { // 2*100/4
		t.Fatalf("kapsam %% 50 beklenirdi, %d", cov.CoveragePct)
	}
	if cov.ByAgentVersion["1.2.0"] != 2 || cov.ByAgentVersion["(bilinmiyor)"] != 1 {
		t.Fatalf("sürüm dağılımı hatalı: %+v", cov.ByAgentVersion)
	}
	if cov.VersionCount != 3 { // 1.2.0, 1.1.0, (bilinmiyor)
		t.Fatalf("farklı sürüm sayısı 3 beklenirdi, %d", cov.VersionCount)
	}
}

func TestCoverageEmpty(t *testing.T) {
	svc := NewService(&memStore{}, newCipher(t))
	cov, err := svc.Coverage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cov.Total != 0 || cov.CoveragePct != 0 {
		t.Fatalf("boş filo: total/pct 0 olmalı: %+v", cov)
	}
}

func TestCoverageStoreError(t *testing.T) {
	store := newRich(&memStore{})
	store.errDevices = errors.New("db down")
	svc := NewService(store, newCipher(t))
	if _, err := svc.Coverage(context.Background()); err == nil {
		t.Fatal("store hatası yayılmalıydı")
	}
}

// --- Incidents / IncidentTimeline -----------------------------------------

func TestIncidents(t *testing.T) {
	store := newRich(&memStore{})
	store.incidents = []IncidentRow{
		{ID: "inc-2", DeviceID: "d1", RuleID: "R1", Severity: "HIGH", Count: 3, Status: "OPEN"},
		{ID: "inc-1", DeviceID: "d2", RuleID: "R2", Severity: "LOW", Count: 1, Status: "RESOLVED"},
	}
	svc := NewService(store, newCipher(t))
	got, err := svc.Incidents(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "inc-2" || got[0].Count != 3 {
		t.Fatalf("incident'ler aynen dönmeliydi: %+v", got)
	}
}

func TestIncidentsError(t *testing.T) {
	store := newRich(&memStore{})
	store.errIncidents = errors.New("boom")
	svc := NewService(store, newCipher(t))
	if _, err := svc.Incidents(context.Background(), 0); err == nil {
		t.Fatal("hata yayılmalıydı")
	}
}

func TestIncidentTimeline(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	store := newRich(&memStore{events: []EventRow{
		// Sıra dışı OccurredAt; kronolojik sıralama beklenir. CreatedAt pencere içinde.
		{ID: "e2", DeviceID: "d1", Category: "SECURITY", Message: "ikinci", OccurredAt: base.Add(2 * time.Minute), CreatedAt: base.Add(2 * time.Minute)},
		{ID: "e1", DeviceID: "d1", Category: "PROCESS", Message: "ilk", OccurredAt: base.Add(1 * time.Minute), CreatedAt: base.Add(1 * time.Minute)},
		{ID: "eOther", DeviceID: "d9", Category: "SECURITY", Message: "başka cihaz", OccurredAt: base, CreatedAt: base},
	}})
	store.incidents = []IncidentRow{
		{ID: "inc-1", DeviceID: "d1", RuleID: "R1", Severity: "HIGH", FirstSeen: base, LastSeen: base.Add(3 * time.Minute), Status: "OPEN"},
	}
	svc := NewService(store, newCipher(t))

	tl, ok, err := svc.IncidentTimeline(context.Background(), "inc-1")
	if err != nil || !ok {
		t.Fatalf("incident bulunmalıydı: ok=%v err=%v", ok, err)
	}
	if tl.Incident.ID != "inc-1" {
		t.Fatalf("incident eşleşmeli: %+v", tl.Incident)
	}
	if len(tl.Events) != 2 {
		t.Fatalf("yalnız d1 olayları (2) beklenirdi: %+v", tl.Events)
	}
	if tl.Events[0].ID != "e1" || tl.Events[1].ID != "e2" {
		t.Fatalf("olaylar kronolojik sıralanmalıydı: %+v", tl.Events)
	}
}

func TestIncidentTimelineNotFound(t *testing.T) {
	store := newRich(&memStore{})
	store.incidents = []IncidentRow{{ID: "inc-1", DeviceID: "d1"}}
	svc := NewService(store, newCipher(t))
	_, ok, err := svc.IncidentTimeline(context.Background(), "yok")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("bulunamayan incident için ok=false beklenirdi")
	}
}

func TestIncidentTimelineError(t *testing.T) {
	store := newRich(&memStore{})
	store.errIncidents = errors.New("boom")
	svc := NewService(store, newCipher(t))
	if _, _, err := svc.IncidentTimeline(context.Background(), "inc-1"); err == nil {
		t.Fatal("hata yayılmalıydı")
	}
}

// --- QueryEvents -----------------------------------------------------------

func TestQueryEvents(t *testing.T) {
	now := time.Now()
	store := &memStore{events: []EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "mimikatz tespit", CreatedAt: now},
		{ID: "e2", Category: "SECURITY", Severity: "LOW", Message: "normal", CreatedAt: now},
	}}
	svc := NewService(store, newCipher(t))
	got, err := svc.QueryEvents(context.Background(), EventFilter{MessageContains: "mimikatz"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "e1" {
		t.Fatalf("MessageContains filtresi yalnız e1 dönmeliydi: %+v", got)
	}
	// newEventDTO şema sürümünü damgalamalı.
	if got[0].SchemaVersion == "" {
		t.Fatalf("schema_version damgalanmalıydı: %+v", got[0])
	}
}

func TestQueryEventsError(t *testing.T) {
	store := newRich(&memStore{})
	store.errQuery = errors.New("boom")
	svc := NewService(store, newCipher(t))
	if _, err := svc.QueryEvents(context.Background(), EventFilter{}); err == nil {
		t.Fatal("hata yayılmalıydı")
	}
}

// --- PendingWipes ----------------------------------------------------------

func TestPendingWipes(t *testing.T) {
	now := time.Now()
	store := newRich(&memStore{})
	store.pendingWipes = []PendingWipeRow{
		{DeviceID: "d1", RequestedBy: "op@x", Reason: "kayıp cihaz", RequestedAt: now},
	}
	svc := NewService(store, newCipher(t))
	got, err := svc.PendingWipes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DeviceID != "d1" || got[0].RequestedBy != "op@x" {
		t.Fatalf("bekleyen wipe aynen dönmeliydi: %+v", got)
	}
}

// --- RunSavedSearches ------------------------------------------------------

func TestRunSavedSearches(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	store := newRich(&memStore{events: []EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "x", CreatedAt: base.Add(time.Hour)},
		{ID: "e2", Category: "SECURITY", Severity: "HIGH", Message: "y", CreatedAt: base.Add(time.Hour)},
		{ID: "e3", Category: "SYSTEM", Severity: "INFO", Message: "z", CreatedAt: base.Add(time.Hour)},
	}})
	store.savedSearches = []SavedSearchRow{
		{ID: "s1", Name: "yüksek güvenlik", Filter: `{"category":"SECURITY","severity":"HIGH"}`},
		{ID: "s2", Name: "eşleşmeyen", Filter: `{"category":"SECURITY","severity":"CRITICAL"}`},
		{ID: "s3", Name: "bozuk", Filter: `not-json`}, // atlanmalı
	}
	svc := NewService(store, newCipher(t))

	hits, err := svc.RunSavedSearches(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("yalnız s1 eşleşmeliydi (bozuk/eşleşmeyen hariç): %+v", hits)
	}
	if hits[0].ID != "s1" || hits[0].Count != 2 {
		t.Fatalf("s1 iki olayla eşleşmeliydi: %+v", hits[0])
	}
}

func TestRunSavedSearchesError(t *testing.T) {
	store := newRich(&memStore{})
	store.errSaved = errors.New("boom")
	svc := NewService(store, newCipher(t))
	if _, err := svc.RunSavedSearches(context.Background(), time.Now()); err == nil {
		t.Fatal("hata yayılmalıydı")
	}
}

// --- SaveSearch / SavedSearches / DeleteSavedSearch ------------------------

func TestSaveSearchTrimsName(t *testing.T) {
	store := newRich(&memStore{})
	svc := NewService(store, newCipher(t))
	row, err := svc.SaveSearch(context.Background(), "  avım  ", `{"category":"SECURITY"}`, "op@x")
	if err != nil {
		t.Fatal(err)
	}
	if row.Name != "avım" {
		t.Fatalf("ad kırpılmalıydı: %q", row.Name)
	}
	if len(store.saveCalls) != 1 || store.saveCalls[0].Name != "avım" || store.saveCalls[0].CreatedBy != "op@x" {
		t.Fatalf("SaveSearch depoya kırpılmış adla iletmeliydi: %+v", store.saveCalls)
	}
}

func TestSavedSearchesPassthrough(t *testing.T) {
	store := newRich(&memStore{})
	store.savedSearches = []SavedSearchRow{{ID: "s1", Name: "a"}, {ID: "s2", Name: "b"}}
	svc := NewService(store, newCipher(t))
	got, err := svc.SavedSearches(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "s1" {
		t.Fatalf("kayıtlı aramalar aynen dönmeliydi: %+v", got)
	}
}

func TestDeleteSavedSearch(t *testing.T) {
	store := newRich(&memStore{})
	svc := NewService(store, newCipher(t))
	if err := svc.DeleteSavedSearch(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if len(store.deletedIDs) != 1 || store.deletedIDs[0] != "s1" {
		t.Fatalf("silinen kimlik depoya iletilmeliydi: %+v", store.deletedIDs)
	}
}

// --- FleetRisk -------------------------------------------------------------

func TestFleetRisk(t *testing.T) {
	now := time.Now()
	store := newRich(&memStore{
		devices: []DeviceRow{
			{ID: "d1", Status: "ACTIVE", LastSeen: now},
			{ID: "d2", Status: "QUARANTINED", LastSeen: now},
		},
		// d1 için en son uyum: disk şifreleme kapalı.
		events: []EventRow{
			{DeviceID: "d1", Category: "SECURITY", CreatedAt: now, Details: []byte(`{"disk_encryption":"off","firewall":"on"}`)},
		},
	})
	store.incidents = []IncidentRow{
		{ID: "inc1", DeviceID: "d1", RuleID: "R1", Severity: "HIGH", Status: "OPEN"},
		{ID: "inc2", DeviceID: "d2", RuleID: "R2", Severity: "CRITICAL", Status: "RESOLVED"}, // atlanmalı
	}
	svc := NewService(store, newCipher(t))

	fr, err := svc.FleetRisk(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.Devices) != 2 {
		t.Fatalf("2 cihaz risk kaydı beklenirdi: %+v", fr.Devices)
	}
	// En riskli cihaz önce (skora göre azalan).
	if fr.Devices[0].Score < fr.Devices[1].Score {
		t.Fatalf("cihazlar skora göre azalan sıralanmalıydı: %+v", fr.Devices)
	}
	if fr.FleetScore <= 0 || fr.FleetBand == "" {
		t.Fatalf("filo skoru/bandı hesaplanmalıydı: %+v", fr)
	}
	// Bands toplamı cihaz sayısına eşit olmalı.
	sum := 0
	for _, n := range fr.Bands {
		sum += n
	}
	if sum != 2 {
		t.Fatalf("band sayımları toplamı 2 olmalı: %+v", fr.Bands)
	}
	// Sürücü açıklamalarını cihaz kimliğine göre topla.
	drv := map[string][]string{}
	for _, d := range fr.Devices {
		drv[d.DeviceID] = d.Drivers
	}
	if !containsSub(drv["d1"], "açık incident") || !containsSub(drv["d1"], "disk şifreleme kapalı") {
		t.Fatalf("d1 sürücüleri açık incident + şifreleme kapalı içermeliydi: %+v", drv["d1"])
	}
	if !containsSub(drv["d2"], "karantinada") {
		t.Fatalf("d2 sürücüleri karantina içermeliydi: %+v", drv["d2"])
	}
	// RESOLVED incident d2 için sürücü üretmemeliydi.
	if containsSub(drv["d2"], "açık incident") {
		t.Fatalf("RESOLVED incident sürücü üretmemeliydi: %+v", drv["d2"])
	}
}

func TestFleetRiskError(t *testing.T) {
	store := newRich(&memStore{})
	store.errDevices = errors.New("boom")
	svc := NewService(store, newCipher(t))
	if _, err := svc.FleetRisk(context.Background()); err == nil {
		t.Fatal("hata yayılmalıydı")
	}
}

func containsSub(list []string, sub string) bool {
	for _, s := range list {
		if len(s) >= len(sub) && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// --- DetectionResponseTrends ----------------------------------------------

func TestDetectionResponseTrends(t *testing.T) {
	now := time.Now()
	created := now.Add(-2 * time.Hour)
	store := &memStore{
		events: []EventRow{
			// SECURITY: alım gecikmesi 60s (MTTD).
			{ID: "e1", Category: "SECURITY", Severity: "HIGH", OccurredAt: created.Add(-time.Minute), CreatedAt: created},
		},
		acks: map[string]EventAck{
			// Triyaj: yanıt süresi 300s (MTTR).
			"e1": {Status: "RESOLVED", AdminEmail: "op@x", At: created.Add(5 * time.Minute)},
		},
	}
	svc := NewService(store, newCipher(t))

	tr, err := svc.DetectionResponseTrends(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if tr.WindowDays != 7 || len(tr.Daily) != 7 {
		t.Fatalf("7 günlük pencere beklenirdi: window=%d daily=%d", tr.WindowDays, len(tr.Daily))
	}
	if tr.DetectN != 1 || tr.MTTDSeconds != 60 {
		t.Fatalf("MTTD 60s / n=1 beklenirdi: %+v", tr)
	}
	if tr.RespondN != 1 || tr.MTTRSeconds != 300 {
		t.Fatalf("MTTR 300s / n=1 beklenirdi: %+v", tr)
	}
}

func TestDetectionResponseTrendsDefaultDays(t *testing.T) {
	svc := NewService(&memStore{}, newCipher(t))
	tr, err := svc.DetectionResponseTrends(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if tr.WindowDays != 7 {
		t.Fatalf("days<=0 varsayılan 7 olmalı: %d", tr.WindowDays)
	}
}

func TestDetectionResponseTrendsError(t *testing.T) {
	store := newRich(&memStore{})
	store.errQuery = errors.New("boom")
	svc := NewService(store, newCipher(t))
	if _, err := svc.DetectionResponseTrends(context.Background(), 7); err == nil {
		t.Fatal("hata yayılmalıydı")
	}
}

// --- Artifacts / ArtifactBytes --------------------------------------------

func TestArtifacts(t *testing.T) {
	at := time.Now()
	store := &memStore{artifacts: []ArtifactRow{
		{ID: "a1", DeviceID: "d1", Path: "/tmp/x", SHA256: "deadbeef", Size: 10, CollectedAt: at},
		{ID: "a2", DeviceID: "d9", Path: "/tmp/y", SHA256: "cafe", Size: 20, CollectedAt: at}, // başka cihaz
	}}
	svc := NewService(store, newCipher(t))
	got, err := svc.Artifacts(context.Background(), "d1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "a1" || got[0].SHA256 != "deadbeef" || got[0].Size != 10 {
		t.Fatalf("yalnız d1 artefaktı dönmeliydi: %+v", got)
	}
}

func TestArtifactBytes(t *testing.T) {
	store := &memStore{artContent: map[string]ArtifactContent{
		"a1": {Path: "/tmp/x", Content: []byte("hello")},
	}}
	svc := NewService(store, newCipher(t))
	c, ok, err := svc.ArtifactBytes(context.Background(), "a1")
	if err != nil || !ok {
		t.Fatalf("artefakt bulunmalıydı: ok=%v err=%v", ok, err)
	}
	if string(c.Content) != "hello" {
		t.Fatalf("içerik dönmeliydi: %q", c.Content)
	}
	if _, ok, _ := svc.ArtifactBytes(context.Background(), "yok"); ok {
		t.Fatal("olmayan artefakt için ok=false beklenirdi")
	}
}

// --- ExportDevice ----------------------------------------------------------

func TestExportDevice(t *testing.T) {
	cipher := newCipher(t)
	hostEnc, _ := cipher.EncryptString("HOST-1")
	now := time.Now()
	store := &memStore{
		devices: []DeviceRow{{ID: "d1", Status: "ACTIVE", HostnameEnc: hostEnc, LastSeen: now}},
		events: []EventRow{
			{ID: "e1", DeviceID: "d1", Category: "SECURITY", Severity: "HIGH", Message: "olay", OccurredAt: now},
		},
		audit: []AuditRow{
			{ID: 1, AdminEmail: "op@x", Action: "QUARANTINE", TargetType: "device", TargetID: "d1", CreatedAt: now},
			{ID: 2, AdminEmail: "op@x", Action: "CREATE_POLICY", TargetType: "policy", TargetID: "p1", CreatedAt: now}, // hariç
			{ID: 3, AdminEmail: "op@x", Action: "WIPE", TargetType: "device", TargetID: "d9", CreatedAt: now},          // başka cihaz
		},
	}
	svc := NewService(store, cipher)

	exp, ok, err := svc.ExportDevice(context.Background(), "d1")
	if err != nil || !ok {
		t.Fatalf("cihaz dışa aktarılmalıydı: ok=%v err=%v", ok, err)
	}
	if exp.DeviceID != "d1" || exp.Device.Device.Hostname != "HOST-1" {
		t.Fatalf("cihaz detayı deşifre edilmeliydi: %+v", exp.Device.Device)
	}
	if len(exp.Events) != 1 {
		t.Fatalf("1 olay beklenirdi: %+v", exp.Events)
	}
	if len(exp.Audit) != 1 || exp.Audit[0].ID != 1 {
		t.Fatalf("yalnız bu cihazı hedefleyen denetim kaydı beklenirdi: %+v", exp.Audit)
	}
	if exp.GeneratedAt.IsZero() {
		t.Fatal("generated_at damgalanmalıydı")
	}
}

func TestExportDeviceNotFound(t *testing.T) {
	svc := NewService(&memStore{}, newCipher(t))
	_, ok, err := svc.ExportDevice(context.Background(), "yok")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("bulunamayan cihaz için ok=false beklenirdi")
	}
}

// --- Policies / LatestSoftwareByDevice ------------------------------------

func TestPolicies(t *testing.T) {
	store := &memStore{policies: []PolicyRow{
		{ID: "p1", Name: "Baseline", Version: "v2", RuleCount: 5, DeviceCount: 20},
	}}
	svc := NewService(store, newCipher(t))
	got, err := svc.Policies(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "p1" || got[0].RuleCount != 5 || got[0].DeviceCount != 20 {
		t.Fatalf("politikalar aynen dönmeliydi: %+v", got)
	}
}

func TestLatestSoftwareByDevice(t *testing.T) {
	store := &memStore{latestSW: map[string][]string{"d1": {"Google Chrome", "7-Zip"}}}
	svc := NewService(store, newCipher(t))
	got, err := svc.LatestSoftwareByDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got["d1"]) != 2 {
		t.Fatalf("d1 yazılım envanteri dönmeliydi: %+v", got)
	}
}

// --- AdminBehavior / FrameworkCompliance ----------------------------------

func TestAdminBehavior(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	// Kısa pencerede 5 yıkıcı eylem → HIGH bulgu (burst eşiği 5).
	audit := []AuditRow{}
	for i := 0; i < 5; i++ {
		audit = append(audit, AuditRow{ID: int64(i + 1), AdminEmail: "rogue@x", Action: "WIPE", CreatedAt: t0.Add(time.Duration(i) * time.Minute)})
	}
	store := &memStore{audit: audit}
	svc := NewService(store, newCipher(t))

	rep, err := svc.AdminBehavior(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Profiles) != 1 || rep.Profiles[0].Admin != "rogue@x" || rep.Profiles[0].Destructive != 5 {
		t.Fatalf("profil beklenirdi (5 yıkıcı): %+v", rep.Profiles)
	}
	foundHigh := false
	for _, f := range rep.Findings {
		if f.Admin == "rogue@x" && f.Severity == "HIGH" {
			foundHigh = true
		}
	}
	if !foundHigh {
		t.Fatalf("yıkıcı-eylem serisi HIGH bulgu üretmeliydi: %+v", rep.Findings)
	}
}

func TestAdminBehaviorError(t *testing.T) {
	svc := NewService(&errAuditStore{}, newCipher(t))
	if _, err := svc.AdminBehavior(context.Background(), 0); err == nil {
		t.Fatal("hata yayılmalıydı")
	}
}

// errAuditStore, ListAudit'te hata döndürür (AdminBehavior hata yolu).
type errAuditStore struct{ memStore }

func (e *errAuditStore) ListAudit(_ context.Context, _ int) ([]AuditRow, error) {
	return nil, errors.New("audit down")
}

func TestFrameworkCompliance(t *testing.T) {
	now := time.Now()
	det := func(enc, fw string) []byte {
		return []byte(`{"disk_encryption":"` + enc + `","firewall":"` + fw + `"}`)
	}
	store := &memStore{events: []EventRow{
		{DeviceID: "d1", Category: "SECURITY", CreatedAt: now, Details: det("on", "on")},
		{DeviceID: "d2", Category: "SECURITY", CreatedAt: now, Details: det("off", "on")},
		{DeviceID: "d3", Category: "SECURITY", CreatedAt: now, Details: det("on", "off")},
		{DeviceID: "d4", Category: "SECURITY", CreatedAt: now, Details: det("unknown", "unknown")}, // sayılmaz
	}}
	svc := NewService(store, newCipher(t))

	rep, err := svc.FrameworkCompliance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Frameworks) == 0 || len(rep.Controls) == 0 {
		t.Fatalf("çerçeve/kontrol skorları üretilmeliydi: %+v", rep)
	}
	// disk_encryption: on olan 2 (d1,d3) / değerlendirilen 3 (d1,d2,d3) → %67.
	var encCtrl *struct {
		pass int
		eval bool
	}
	for _, c := range rep.Controls {
		if c.Control == "disk_encryption" {
			encCtrl = &struct {
				pass int
				eval bool
			}{c.PassPct, c.Evaluated}
		}
	}
	if encCtrl == nil || !encCtrl.eval || encCtrl.pass != 67 {
		t.Fatalf("disk_encryption uyum oranı %%67 beklenirdi: %+v", encCtrl)
	}
}

// --- helpers: clampLimit / nonNilTags / sevRankValue / edgeKind -----------

func TestClampLimit(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 100}, {-5, 100}, {1, 1}, {500, 500}, {1000, 1000}, {1001, 1000}, {99999, 1000},
	}
	for _, c := range cases {
		if got := clampLimit(c.in); got != c.want {
			t.Errorf("clampLimit(%d)=%d beklenen %d", c.in, got, c.want)
		}
	}
}

func TestNonNilTags(t *testing.T) {
	if got := nonNilTags(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil → boş dizi beklenirdi: %#v", got)
	}
	in := []string{"a", "b"}
	if got := nonNilTags(in); len(got) != 2 || got[0] != "a" {
		t.Fatalf("dolu dilim aynen dönmeliydi: %#v", got)
	}
}

func TestDecryptEmptyBlob(t *testing.T) {
	svc := NewService(&memStore{}, newCipher(t))
	if got := svc.decrypt(nil); got != "" {
		t.Fatalf("boş blob → boş string beklenirdi: %q", got)
	}
	if got := svc.decrypt([]byte{}); got != "" {
		t.Fatalf("boş blob → boş string beklenirdi: %q", got)
	}
}

func TestSevRankValue(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"CRITICAL", 5}, {"critical", 5}, {"HIGH", 4}, {"MEDIUM", 3},
		{"LOW", 2}, {"INFO", 1}, {"", 0}, {"BOGUS", 0},
	}
	for _, c := range cases {
		if got := sevRankValue(c.in); got != c.want {
			t.Errorf("sevRankValue(%q)=%d beklenen %d", c.in, got, c.want)
		}
	}
}

func TestEdgeKind(t *testing.T) {
	cases := []struct{ typ, want string }{
		{"process", "ran"}, {"ip", "connected"}, {"domain", "resolved"},
		{"file", "touched"}, {"unknown", "related"}, {"", "related"},
	}
	for _, c := range cases {
		if got := edgeKind(c.typ); got != c.want {
			t.Errorf("edgeKind(%q)=%q beklenen %q", c.typ, got, c.want)
		}
	}
}

// --- entityFromEvent (kalan dallar) ---------------------------------------

func TestEntityFromEvent(t *testing.T) {
	cases := []struct {
		name    string
		cat     string
		details map[string]any
		wantTyp string
		wantVal string
		wantOK  bool
	}{
		{"process by name", "PROCESS", map[string]any{"name": "cmd.exe"}, "process", "cmd.exe", true},
		{"process by image", "PROCESS", map[string]any{"image": "c:\\a.exe"}, "process", "c:\\a.exe", true},
		{"process none", "PROCESS", map[string]any{"foo": "bar"}, "", "", false},
		{"conn by ip", "NETWORK_CONN", map[string]any{"ip": "1.1.1.1"}, "ip", "1.1.1.1", true},
		{"conn by remote", "NETWORK_CONN", map[string]any{"remote": "2.2.2.2"}, "ip", "2.2.2.2", true},
		{"discovery domain", "NETWORK_DISCOVERY", map[string]any{"domain": "corp.local"}, "domain", "corp.local", true},
		{"discovery mac fallback", "NETWORK_DISCOVERY", map[string]any{"mac": "aa:bb"}, "ip", "aa:bb", true},
		{"discovery ip fallback", "NETWORK_DISCOVERY", map[string]any{"ip": "3.3.3.3"}, "ip", "3.3.3.3", true},
		{"security parent domain", "SECURITY", map[string]any{"parent": "evil.com"}, "domain", "evil.com", true},
		{"policy path file", "POLICY_VIOLATION", map[string]any{"path": "/etc/shadow"}, "file", "/etc/shadow", true},
		{"security remote_ip", "SECURITY", map[string]any{"remote_ip": "4.4.4.4"}, "ip", "4.4.4.4", true},
		{"security ip", "SECURITY", map[string]any{"ip": "5.5.5.5"}, "ip", "5.5.5.5", true},
		{"unknown category", "SYSTEM", map[string]any{"domain": "x"}, "", "", false},
		{"security empty", "SECURITY", map[string]any{}, "", "", false},
		{"blank value skipped", "PROCESS", map[string]any{"process": "   "}, "", "", false},
	}
	for _, c := range cases {
		typ, val, ok := entityFromEvent(c.cat, c.details)
		if ok != c.wantOK || typ != c.wantTyp || val != c.wantVal {
			t.Errorf("%s: entityFromEvent(%q,%v)=(%q,%q,%v) beklenen (%q,%q,%v)",
				c.name, c.cat, c.details, typ, val, ok, c.wantTyp, c.wantVal, c.wantOK)
		}
	}
}

// --- Service sarmalayıcılar: DeviceAttackStory / DeviceEntityGraph ---------

func TestDeviceAttackStoryWrapper(t *testing.T) {
	now := time.Now()
	store := &memStore{events: []EventRow{
		{ID: "e1", DeviceID: "d1", Category: "PROCESS", Severity: "MEDIUM", Message: "powershell çalıştı", OccurredAt: now},
		{ID: "e2", DeviceID: "d1", Category: "SYSTEM", Severity: "INFO", Message: "rutin", OccurredAt: now}, // hariç
	}}
	svc := NewService(store, newCipher(t))
	story, err := svc.DeviceAttackStory(context.Background(), "d1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if story.DeviceID != "d1" || len(story.Steps) != 1 || story.Steps[0].Stage != "Execution" {
		t.Fatalf("saldırı hikâyesi beklenmedik: %+v", story)
	}
}

func TestDeviceEntityGraphWrapper(t *testing.T) {
	now := time.Now()
	store := &memStore{events: []EventRow{
		{ID: "e1", DeviceID: "d1", Category: "NETWORK_CONN", Severity: "HIGH", OccurredAt: now, Details: []byte(`{"remote_ip":"1.2.3.4"}`)},
	}}
	svc := NewService(store, newCipher(t))
	g, err := svc.DeviceEntityGraph(context.Background(), "d1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if g.DeviceID != "d1" || len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("varlık grafiği beklenmedik: %+v", g)
	}
	if g.Edges[0].Kind != "connected" || g.Edges[0].To != "ip:1.2.3.4" {
		t.Fatalf("kenar beklenmedik: %+v", g.Edges[0])
	}
}

// --- activateForReplay -----------------------------------------------------

func TestActivateForReplay(t *testing.T) {
	if got := activateForReplay(nil); got != nil {
		t.Fatalf("boş kural seti nil dönmeliydi (varsayılan set): %+v", got)
	}
	if got := activateForReplay([]detect.Rule{}); got != nil {
		t.Fatalf("boş kural seti nil dönmeliydi: %+v", got)
	}
	orig := []detect.Rule{
		{ID: "R1", Name: "draft kural", Status: "draft"},
		{ID: "R2", Name: "retired kural", Status: "retired"},
	}
	out := activateForReplay(orig)
	if len(out) != 2 || out[0].Status != "active" || out[1].Status != "active" {
		t.Fatalf("tüm kurallar aktifleştirilmeliydi: %+v", out)
	}
	// Orijinal değişmemeli.
	if orig[0].Status != "draft" || orig[1].Status != "retired" {
		t.Fatalf("orijinal kurallar değiştirilmemeliydi: %+v", orig)
	}
}
