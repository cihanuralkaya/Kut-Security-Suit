package connectors

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNormalizersSmoke, CEF/LEEF/JSON/WinEvent normalizer adaptörlerinin geçerli ham
// kayıtları kanonik olaya çevirdiğini doğrular (§29).
func TestNormalizersSmoke(t *testing.T) {
	// CEF.
	cefEvs, err := CEFNormalizer("CEF:0|KUT|FW|1.0|100|Erişim reddedildi|5|src=1.2.3.4", tnow)
	if err != nil || len(cefEvs) != 1 {
		t.Fatalf("CEF normalize: %v (%d)", err, len(cefEvs))
	}
	if !strings.Contains(cefEvs[0].Message, "KUT/FW") {
		t.Errorf("CEF kaynak mesaja işlenmeli: %+v", cefEvs[0])
	}

	// LEEF (sekme ayraçlı öznitelikler).
	leefEvs, err := LEEFNormalizer("LEEF:1.0|KUT|IDP|1.0|EID42|msg=oturum reddi\tsev=8", tnow)
	if err != nil || len(leefEvs) != 1 {
		t.Fatalf("LEEF normalize: %v (%d)", err, len(leefEvs))
	}
	if !strings.Contains(leefEvs[0].Message, "oturum reddi") {
		t.Errorf("LEEF msg alınmalı: %+v", leefEvs[0])
	}

	// JSON (tek nesne).
	jsonEvs, err := JSONNormalizer(`{"source":"app","message":"merhaba","severity":"HIGH","category":"SECURITY"}`, tnow)
	if err != nil || len(jsonEvs) != 1 {
		t.Fatalf("JSON normalize: %v (%d)", err, len(jsonEvs))
	}
	if jsonEvs[0].Severity != "HIGH" {
		t.Errorf("JSON severity korunmalı: %+v", jsonEvs[0])
	}

	// WinEvent (tek nesne).
	winEvs, err := WinEventNormalizer(`{"event_id":4625,"computer_name":"PC1"}`, tnow)
	if err != nil || len(winEvs) != 1 {
		t.Fatalf("WinEvent normalize: %v (%d)", err, len(winEvs))
	}
	if !strings.Contains(winEvs[0].Message, "EventID 4625") {
		t.Errorf("WinEvent event id mesaja işlenmeli: %+v", winEvs[0])
	}

	// Geçersiz ham kayıt → hata döner (adaptör hatayı iletir).
	if _, err := CEFNormalizer("geçersiz-satır", tnow); err == nil {
		t.Error("CEF öneki yoksa hata dönmeli")
	}
}

// TestCloudNormalizerGCPAndM365, CloudNormalizer'ın gcp/m365 sağlayıcıları için
// kaynağı doğru damgaladığını doğrular (§30).
func TestCloudNormalizerGCPAndM365(t *testing.T) {
	gcp := CloudNormalizer("gcp")
	evs, err := gcp(`{"eventName":"storage.buckets.get","requestID":"r1"}`, tnow)
	if err != nil || len(evs) != 1 {
		t.Fatalf("gcp normalize: %v (%d)", err, len(evs))
	}
	if evs[0].Source != "cloud/gcp" || evs[0].CorrelationID != "cloud_r1" {
		t.Errorf("gcp source/correlation hatalı: %+v", evs[0])
	}

	m365 := CloudNormalizer("m365")
	evs, err = m365(`{"eventName":"UserLoggedIn"}`, tnow)
	if err != nil || len(evs) != 1 {
		t.Fatalf("m365 normalize: %v (%d)", err, len(evs))
	}
	if evs[0].Source != "cloud/m365" || evs[0].CorrelationID != "" {
		t.Errorf("m365 source/correlation hatalı: %+v", evs[0])
	}
}

// TestCloudAuditActor, actor() çözümünü doğrular: Caller > userIdentity.arn >
// userIdentity.userName > boş.
func TestCloudAuditActor(t *testing.T) {
	if a := (cloudAudit{Caller: "svc-1"}).actor(); a != "svc-1" {
		t.Errorf("Caller öncelikli olmalı: %q", a)
	}
	if a := (cloudAudit{UserIdentity: []byte(`{"arn":"arn:aws:iam::1:user/bob"}`)}).actor(); a != "arn:aws:iam::1:user/bob" {
		t.Errorf("arn alınmalı: %q", a)
	}
	if a := (cloudAudit{UserIdentity: []byte(`{"userName":"alice"}`)}).actor(); a != "alice" {
		t.Errorf("userName alınmalı: %q", a)
	}
	if a := (cloudAudit{}).actor(); a != "" {
		t.Errorf("aktör yoksa boş olmalı: %q", a)
	}
}

// TestCloudAuditSeverity, severity() eşlemesini doğrular: başarısız-oturum → HIGH,
// başarısız-genel → MEDIUM, başarılı → INFO.
func TestCloudAuditSeverity(t *testing.T) {
	if s := (cloudAudit{EventName: "ConsoleLogin", ErrorCode: "Failed"}).severity(); s != "HIGH" {
		t.Errorf("başarısız login HIGH olmalı: %q", s)
	}
	if s := (cloudAudit{EventName: "PutObject", ResultType: "failure"}).severity(); s != "MEDIUM" {
		t.Errorf("başarısız genel MEDIUM olmalı: %q", s)
	}
	if s := (cloudAudit{EventName: "GetObject"}).severity(); s != "INFO" {
		t.Errorf("başarılı olay INFO olmalı: %q", s)
	}
}

// TestCloudAuditWhen, when() zaman çözümünü doğrular: RFC3339 çözülür, hiçbiri yoksa
// now fallback döner.
func TestCloudAuditWhen(t *testing.T) {
	want := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	if got := (cloudAudit{EventTime: "2026-09-01T10:00:00Z"}).when(tnow); !got.Equal(want) {
		t.Errorf("EventTime çözülmeli: %v", got)
	}
	if got := (cloudAudit{TimeGenerated: "2026-09-01T10:00:00Z"}).when(tnow); !got.Equal(want) {
		t.Errorf("TimeGenerated çözülmeli: %v", got)
	}
	// Hiçbir zaman damgası yok → now fallback.
	if got := (cloudAudit{}).when(tnow); !got.Equal(tnow.UTC()) {
		t.Errorf("zaman yoksa now fallback olmalı: %v", got)
	}
	// Geçersiz format → now fallback.
	if got := (cloudAudit{Timestamp: "not-a-time"}).when(tnow); !got.Equal(tnow.UTC()) {
		t.Errorf("geçersiz zamanda now fallback olmalı: %v", got)
	}
}

// TestCloudAuditEventName, eventName() öncelik zincirini doğrular: EventName >
// EventType > OperationName(string) > OperationName{value} > "cloud-event".
func TestCloudAuditEventName(t *testing.T) {
	if n := (cloudAudit{EventName: "A"}).eventName(); n != "A" {
		t.Errorf("EventName öncelikli: %q", n)
	}
	if n := (cloudAudit{EventType: "B"}).eventName(); n != "B" {
		t.Errorf("EventType alınmalı: %q", n)
	}
	if n := (cloudAudit{OperationName: "C"}).eventName(); n != "C" {
		t.Errorf("OperationName string alınmalı: %q", n)
	}
	if n := (cloudAudit{OperationName: map[string]any{"value": "D"}}).eventName(); n != "D" {
		t.Errorf("OperationName.value alınmalı: %q", n)
	}
	if n := (cloudAudit{}).eventName(); n != "cloud-event" {
		t.Errorf("fallback cloud-event olmalı: %q", n)
	}
}

// TestCloudCorrelationEmpty, boş requestID'de korelasyon kimliğinin boş kaldığını
// doğrular.
func TestCloudCorrelationEmpty(t *testing.T) {
	if c := cloudCorrelation(""); c != "" {
		t.Errorf("boş requestID boş korelasyon vermeli: %q", c)
	}
	if c := cloudCorrelation("x"); c != "cloud_x" {
		t.Errorf("dolu requestID cloud_ öneki almalı: %q", c)
	}
}

// TestFilePuller, FilePuller'ın satır modu, tam-belge modu ve eksik-dosya hatasını
// doğrular.
func TestFilePuller(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.log")
	if err := os.WriteFile(path, []byte("l1\nl2\nl3\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Satır modu: her satır bir kayıt.
	lines, err := FilePuller(path, false)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[0] != "l1" || lines[2] != "l3" {
		t.Fatalf("satır modu 3 kayıt dönmeliydi: %+v", lines)
	}

	// Tam-belge modu: tek kayıt (tüm dosya).
	whole, err := FilePuller(path, true)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(whole) != 1 || !strings.Contains(whole[0], "l1") || !strings.Contains(whole[0], "l3") {
		t.Fatalf("tam-belge modu tek kayıt dönmeliydi: %+v", whole)
	}

	// Eksik dosya → hata.
	if _, err := FilePuller(filepath.Join(dir, "yok.log"), false)(context.Background()); err == nil {
		t.Error("eksik dosya hata dönmeli")
	}
}

// TestFetchSkipsBlankAndErrors, Fetch'in boş ham kayıtları ve normalize hatası veren
// kayıtları ATLADIĞINI, puller hatasını ise İLETTİĞİNİ doğrular.
func TestFetchSkipsBlankAndErrors(t *testing.T) {
	// Boş + geçersiz + geçerli karışımı: yalnız geçerli olay üretilir.
	c := NewCEFConnector("cef", SlicePuller([]string{
		"", "   ", "çöp-satır-cef-değil", "CEF:0|V|P|1|1|isim|3|",
	}))
	c.now = func() time.Time { return tnow }
	evs, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("best-effort Fetch hata dönmemeli: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("yalnız geçerli kayıt olay üretmeli: %d", len(evs))
	}

	// Puller hatası → Fetch hatayı iletir.
	errPull := func(context.Context) ([]string, error) { return nil, errors.New("puller patladı") }
	c2 := NewCEFConnector("cef2", errPull)
	if _, err := c2.Fetch(context.Background()); err == nil {
		t.Error("puller hatası Fetch'ten dönmeli")
	}
}

// TestBuildFormatsAndValidation, Build'in leef/json/winevent formatlarını ve girdi
// doğrulamasını (boş ad, boş kaynak, bilinmeyen format) kapsar.
func TestBuildFormatsAndValidation(t *testing.T) {
	for _, tc := range []struct{ fmtName, kind string }{
		{"leef", "siem"}, {"json", "endpoint"}, {"winevent", "identity"},
	} {
		c, err := Build(SourceConfig{Name: "c-" + tc.fmtName, Format: tc.fmtName, Source: "x.log"})
		if err != nil {
			t.Fatalf("%s Build hatası: %v", tc.fmtName, err)
		}
		if c.Kind() != tc.kind {
			t.Errorf("%s kind=%q beklenen %q", tc.fmtName, c.Kind(), tc.kind)
		}
	}
	if _, err := Build(SourceConfig{Format: "cef", Source: "x"}); err == nil {
		t.Error("boş ad hata dönmeli")
	}
	if _, err := Build(SourceConfig{Name: "x", Format: "cef"}); err == nil {
		t.Error("boş kaynak hata dönmeli")
	}
	if _, err := Build(SourceConfig{Name: "x", Format: "bogus", Source: "s"}); err == nil {
		t.Error("bilinmeyen format hata dönmeli")
	}
}

// TestLoadConfig, LoadConfig'in geçerli dosya, eksik dosya ve bozuk JSON durumlarını
// doğrular.
func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(good, []byte(`[{"name":"a","format":"cef","source":"a.log","interval_sec":5}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgs, err := LoadConfig(good)
	if err != nil || len(cfgs) != 1 {
		t.Fatalf("geçerli config yüklenmeliydi: %v (%d)", err, len(cfgs))
	}
	if cfgs[0].Name != "a" || cfgs[0].Interval() != 5*time.Second {
		t.Errorf("config alanları çözülmeliydi: %+v", cfgs[0])
	}

	// Eksik dosya → hata.
	if _, err := LoadConfig(filepath.Join(dir, "yok.json")); err == nil {
		t.Error("eksik config hata dönmeli")
	}

	// Bozuk JSON → hata.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{ bozuk`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil {
		t.Error("bozuk JSON hata dönmeli")
	}
}
