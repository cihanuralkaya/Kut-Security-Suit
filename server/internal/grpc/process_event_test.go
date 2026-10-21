package grpc

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/correlate"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/mitre"
	"kut.corp/suite/server/internal/model"
)

// Bu dosya, ProcessEvent'in ORKESTRASYONUNU/PRECEDENCE'ını (tespit → bit → eşik →
// korelasyon → alarm; eşleşme yoksa jenerik yol) uçtan uca doğrular. Tekil kapılar
// (bits/threshold/correlate) kendi paketlerinde test edilir; buradaki test, bir refactor'un
// kapı SIRASINI veya bir `continue` kısa-devresini sessizce bozmasını yakalar (crown-jewel path).

func newProcHandler(rules []detect.Rule) (*AgentHandler, *fakeAlerter, *fakeAdmin) {
	h := NewAgentHandler(&fakeDevices{}, &fakeEvents{}, nil, &fakeUpdates{}, nil)
	al := &fakeAlerter{}
	h.SetAlerter(al)
	adm := &fakeAdmin{}
	h.SetAdminNotifier(adm)
	if rules != nil {
		h.SetDetector(detect.NewEngine(rules))
	}
	return h, al, adm
}

// tenantAdmin, hem AdminNotifier hem AdminTenantNotifier'ı karşılar (kiracı-atıflı yol testi).
type tenantAdmin struct {
	lastTenant string
	events     int
	tenantHits int
	devTenants []string // PublishTenantDevice kiracıları (sıralı)
}

func (t *tenantAdmin) PublishEvent(string, string, string) { t.events++ }
func (t *tenantAdmin) PublishDevice(string)                {}
func (t *tenantAdmin) PublishTenantEvent(tenant, _, _, _ string) {
	t.lastTenant = tenant
	t.tenantHits++
}
func (t *tenantAdmin) PublishTenantDevice(tenant, _ string) {
	t.devTenants = append(t.devTenants, tenant)
}

// SetTenant + kiracı-farkındalı admin: ProcessEvent olayı sunucu kiracısıyla atıflayıp
// PublishTenantEvent'i çağırmalı (klasik PublishEvent'i DEĞİL).
func TestProcessEventBindsServerTenant(t *testing.T) {
	h, _, _ := newProcHandler([]detect.Rule{})
	adm := &tenantAdmin{}
	h.SetAdminNotifier(adm)
	h.SetTenant("acme")
	h.ProcessEvent(context.Background(), "dev1", model.Event{Category: "x", Message: "y", Severity: "LOW"})
	if adm.tenantHits != 1 || adm.lastTenant != "acme" {
		t.Fatalf("kiracı-atıflı yayın beklenir (tenant=acme): hits=%d tenant=%q events=%d",
			adm.tenantHits, adm.lastTenant, adm.events)
	}
	if adm.events != 0 {
		t.Fatalf("kiracı-farkındalı admin'de klasik PublishEvent çağrılmamalı, events=%d", adm.events)
	}
}

// procCorrSink, korelatör için minimal Sink sahtesidir.
type procCorrSink struct{ opened int }

func (s *procCorrSink) OpenIncident(context.Context, string, string, string, string, string, string, time.Time) (string, error) {
	s.opened++
	return "inc", nil
}
func (s *procCorrSink) BumpIncident(context.Context, string, time.Time) error { return nil }

// Eşleşen kural: ADLANDIRILMIŞ alarm (kural adı + normalize önem + MITRE) üretmeli;
// canlı konsola da push edilmeli.
func TestProcessEventMatchFires(t *testing.T) {
	h, al, adm := newProcHandler([]detect.Rule{{
		ID: "R-M", Name: "kötücül", Category: "proc", Contains: []string{"evil"},
		Severity: "HIGH", Technique: mitre.Technique{ID: "T1059", Name: "Cmd", Tactic: "Execution"},
	}})
	h.ProcessEvent(context.Background(), "dev1", model.Event{Category: "proc", Message: "evil now", Severity: "LOW"})

	alerts := al.all()
	if len(alerts) != 1 {
		t.Fatalf("1 alarm beklenir, %d", len(alerts))
	}
	a := alerts[0]
	if a.Severity != "HIGH" || a.Message != "[kötücül] evil now" || a.TechniqueID != "T1059" {
		t.Fatalf("adlandırılmış alarm içeriği hatalı: %+v", a)
	}
	if adm.events != 1 {
		t.Fatalf("canlı konsol push beklenir, events=%d", adm.events)
	}
}

// Eşleşme yok: jenerik yol — ham önem + kural-öneki OLMADAN mesaj.
func TestProcessEventNoMatchGeneric(t *testing.T) {
	h, al, _ := newProcHandler([]detect.Rule{}) // boş motor → eşleşme yok
	h.ProcessEvent(context.Background(), "dev1", model.Event{Category: "net", Message: "hello", Severity: "MEDIUM"})

	alerts := al.all()
	if len(alerts) != 1 {
		t.Fatalf("jenerik yol 1 alarm üretmeli, %d", len(alerts))
	}
	if alerts[0].Severity != "MEDIUM" || alerts[0].Message != "hello" {
		t.Fatalf("jenerik alarm ham önem/mesaj taşımalı: %+v", alerts[0])
	}
}

// Tekrar-eşiği: Count'a ULAŞILMADAN alarm çıkmamalı, ulaşınca çıkmalı.
func TestProcessEventThresholdGatesThenFires(t *testing.T) {
	h, al, _ := newProcHandler([]detect.Rule{{
		ID: "R-T", Name: "sprey", Category: "auth", Contains: []string{"fail"},
		Severity: "MEDIUM", Threshold: &detect.ThresholdSpec{Count: 2, Seconds: 3600},
	}})
	ev := model.Event{Category: "auth", Message: "login fail", Severity: "LOW"}
	h.ProcessEvent(context.Background(), "devT", ev)
	if n := len(al.all()); n != 0 {
		t.Fatalf("eşik altında alarm olmamalı, %d", n)
	}
	h.ProcessEvent(context.Background(), "devT", ev) // 2. → Count=2'ye ulaşır
	if n := len(al.all()); n != 1 {
		t.Fatalf("eşik dolunca 1 alarm beklenir, %d", n)
	}
}

// Korelasyon: penceredeki İKİNCİ aynı tespit BASTIRILMALI (alarm-fırtınası önleme).
func TestProcessEventCorrelatorSuppresses(t *testing.T) {
	h, al, _ := newProcHandler([]detect.Rule{{
		ID: "R-M", Name: "kötücül", Category: "proc", Contains: []string{"evil"}, Severity: "HIGH",
	}})
	h.SetCorrelator(correlate.New(time.Hour, &procCorrSink{}))
	ev := model.Event{Category: "proc", Message: "evil", Severity: "HIGH"}
	h.ProcessEvent(context.Background(), "devC", ev)
	h.ProcessEvent(context.Background(), "devC", ev) // aynı cihaz+kural → bastırılır
	if n := len(al.all()); n != 1 {
		t.Fatalf("korelasyon ikinci alarmı bastırmalı (toplam 1), %d", n)
	}
}

// recObserver, export tap'ine giden çağrıları kaydeder (deviceID + admitted sayısı + kural id'leri).
type recObserver struct {
	calls []struct {
		deviceID string
		admitted int
		rules    []string
	}
}

func (r *recObserver) ObserveProcessed(_ context.Context, deviceID string, _ model.Event, admitted []detect.Detection) {
	var rules []string
	for _, d := range admitted {
		rules = append(rules, d.RuleID)
	}
	r.calls = append(r.calls, struct {
		deviceID string
		admitted int
		rules    []string
	}{deviceID, len(admitted), rules})
}

// Export tap: ProcessEvent HER olay için gözlemciyi çağırmalı ve yalnızca kapıdan
// GEÇEN tespitleri devretmeli — canlı alarm sayısıyla birebir. Eşik altındaki ilk
// olay admitted=0, eşiğe ulaşan ikinci olay admitted=1 vermeli. Gözlemci tespiti
// DEĞİŞTİRMEMELİ (sona eklendi, gate durumuna dokunmaz).
func TestProcessEventFeedsExportTap(t *testing.T) {
	h, al, _ := newProcHandler([]detect.Rule{{
		ID: "R-T", Name: "sprey", Category: "auth", Contains: []string{"fail"},
		Severity: "MEDIUM", Threshold: &detect.ThresholdSpec{Count: 2, Seconds: 3600},
	}})
	obs := &recObserver{}
	h.SetProcessedObserver(obs)
	ev := model.Event{Category: "auth", Message: "login fail", Severity: "LOW"}
	h.ProcessEvent(context.Background(), "devT", ev) // eşik altı → gated
	h.ProcessEvent(context.Background(), "devT", ev) // Count=2 → ateşler

	if len(obs.calls) != 2 {
		t.Fatalf("tap her olay için çağrılmalı (2), alinan %d", len(obs.calls))
	}
	if obs.calls[0].admitted != 0 {
		t.Errorf("gated olay admitted=0 olmalı, alinan %d", obs.calls[0].admitted)
	}
	if obs.calls[1].admitted != 1 {
		t.Errorf("ateşleyen olay admitted=1 olmalı, alinan %d", obs.calls[1].admitted)
	}
	if n := len(al.all()); n != 1 {
		t.Errorf("tap admitted toplamı canlı alarm sayısıyla eşleşmeli (1), alinan %d", n)
	}
}

// Kural eşleşmese bile ham olay tap'e verilmeli (SIEM'e ham telemetri export'u).
func TestProcessEventTapObservesRawEvent(t *testing.T) {
	h, _, _ := newProcHandler([]detect.Rule{})
	obs := &recObserver{}
	h.SetProcessedObserver(obs)
	h.ProcessEvent(context.Background(), "d1", model.Event{Category: "net", Message: "hello"})
	if len(obs.calls) != 1 || obs.calls[0].admitted != 0 {
		t.Fatalf("eşleşmesiz ham olay admitted=0 ile 1 kez gözlemlenmeli, alinan %+v", obs.calls)
	}
}

// Export paritesi: IoC alarmı tap'e "ioc" tespiti olarak gitmeli (konsol/webhook
// ile aynı alarmlar). Jenerik eşleşmesiz alarm ise tap'e GİTMEMELİ — o ham olay
// zaten EventSink ile export edilir (finding'e çevrilmez).
func TestProcessEventIocFeedsTap(t *testing.T) {
	h, al, _ := newProcHandler([]detect.Rule{}) // kural yok → jenerik + IoC yolu
	h.SetIoCSet(loadIoC(t, "1.2.3.4 c2-a"))
	obs := &recObserver{}
	h.SetProcessedObserver(obs)
	h.ProcessEvent(context.Background(), "devI",
		model.Event{Category: "net", Message: "beacon to 1.2.3.4", Severity: "LOW"})

	if len(obs.calls) != 1 {
		t.Fatalf("tek olay 1 kez gözlemlenmeli, alinan %d", len(obs.calls))
	}
	// Tap yalnız IoC tespitini taşımalı (jenerik alarm ham olay olarak EventSink'te).
	if len(obs.calls[0].rules) != 1 || obs.calls[0].rules[0] != "ioc" {
		t.Fatalf("tap'e yalnız 'ioc' tespiti gitmeliydi, alinan %v", obs.calls[0].rules)
	}
	// Operatör yolu HEM jenerik HEM IoC alarmını görür (parite: tap IoC'yi finding yapar).
	if n := len(al.all()); n != 2 {
		t.Errorf("webhook/konsol jenerik+ioc = 2 alarm görmeli, alinan %d", n)
	}
}

// Çok-aşamalı bitler: Require sağlanmadan alarm çıkmamalı; bir Set kuralı ön-koşulu
// kurduktan sonra Require kuralı ateşlemeli (aşama-1 → aşama-2 precedence).
func TestProcessEventBitsRequireGateThenSet(t *testing.T) {
	h, al, _ := newProcHandler([]detect.Rule{
		{ID: "R-S", Name: "asama1", Category: "stg", Contains: []string{"s1"}, Severity: "LOW",
			Bits: &detect.BitSpec{Set: []string{"b1"}}},
		{ID: "R-R", Name: "asama2", Category: "stg", Contains: []string{"s2"}, Severity: "HIGH",
			Bits: &detect.BitSpec{Require: []string{"b1"}}},
	})
	dev := "devB"
	// Aşama-2 önce: ön-koşul (b1) yok → gated (alarm yok).
	h.ProcessEvent(context.Background(), dev, model.Event{Category: "stg", Message: "s2", Severity: "HIGH"})
	if n := len(al.all()); n != 0 {
		t.Fatalf("ön-koşul yokken aşama-2 gated olmalı, %d alarm", n)
	}
	// Aşama-1: eşleşir → ateşler + b1'i kurar.
	h.ProcessEvent(context.Background(), dev, model.Event{Category: "stg", Message: "s1", Severity: "LOW"})
	if n := len(al.all()); n != 1 {
		t.Fatalf("aşama-1 ateşlemeli (b1 kurulur), toplam 1 beklenir, %d", n)
	}
	// Aşama-2 tekrar: b1 artık kurulu → ateşler.
	h.ProcessEvent(context.Background(), dev, model.Event{Category: "stg", Message: "s2", Severity: "HIGH"})
	if n := len(al.all()); n != 2 {
		t.Fatalf("b1 kurulunca aşama-2 ateşlemeli, toplam 2 beklenir, %d", n)
	}
}
