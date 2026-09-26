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
}

func (t *tenantAdmin) PublishEvent(string, string, string) { t.events++ }
func (t *tenantAdmin) PublishDevice(string)                {}
func (t *tenantAdmin) PublishTenantEvent(tenant, _, _, _ string) {
	t.lastTenant = tenant
	t.tenantHits++
}
func (t *tenantAdmin) PublishTenantDevice(string, string) {}

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
