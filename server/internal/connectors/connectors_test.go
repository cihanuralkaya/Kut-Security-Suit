package connectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/connector"
)

var tnow = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func TestSyslogConnector(t *testing.T) {
	c := NewSyslogConnector("fw-syslog", SlicePuller([]string{
		"<34>Oct 11 22:14:15 host app: erişim reddedildi",
	}))
	c.now = func() time.Time { return tnow }
	evs, err := c.Fetch(context.Background())
	if err != nil || len(evs) != 1 {
		t.Fatalf("1 olay beklenir: %v (%d)", err, len(evs))
	}
	if evs[0].Source != "syslog" && !strings.Contains(evs[0].Message, "host") {
		t.Errorf("syslog normalize hatalı: %+v", evs[0])
	}
	if c.Kind() != "network" {
		t.Errorf("kind network olmalı: %q", c.Kind())
	}
}

func TestCloudConnectorAWS(t *testing.T) {
	body := `[{"eventTime":"2026-09-01T10:00:00Z","eventName":"ConsoleLogin","errorCode":"Failed",
	  "sourceIPAddress":"1.2.3.4","requestID":"req-9","userIdentity":{"arn":"arn:aws:iam::1:user/bob"}}]`
	c := NewCloudConnector("aws-trail", "aws", SlicePuller([]string{body}))
	c.now = func() time.Time { return tnow }
	evs, err := c.Fetch(context.Background())
	if err != nil || len(evs) != 1 {
		t.Fatalf("1 bulut olayı beklenir: %v (%d)", err, len(evs))
	}
	e := evs[0]
	if e.Source != "cloud/aws" || e.EventType != "ConsoleLogin" {
		t.Errorf("bulut source/event_type hatalı: %+v", e)
	}
	if e.Severity != "HIGH" {
		t.Errorf("başarısız ConsoleLogin HIGH olmalı: %q", e.Severity)
	}
	if e.CorrelationID != "cloud_req-9" {
		t.Errorf("correlation requestID'den gelmeli: %q", e.CorrelationID)
	}
	if !strings.Contains(e.Details, "1.2.3.4") || !strings.Contains(e.Message, "arn:aws") {
		t.Errorf("ip/actor işlenmeli: %+v", e)
	}
	// occurred_at bulut zaman damgasından
	if !e.OccurredAt.Equal(time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("eventTime çözülmeli: %v", e.OccurredAt)
	}
}

func TestCloudConnectorAzureSingleObject(t *testing.T) {
	body := `{"operationName":{"value":"Microsoft.Authorization/roleAssignments/write"},
	  "timeGenerated":"2026-09-02T08:00:00Z","callerIpAddress":"5.6.7.8","resultType":"Success"}`
	c := NewCloudConnector("azure-activity", "azure", SlicePuller([]string{body}))
	c.now = func() time.Time { return tnow }
	evs, err := c.Fetch(context.Background())
	if err != nil || len(evs) != 1 {
		t.Fatalf("azure tek nesne: %v (%d)", err, len(evs))
	}
	if evs[0].EventType != "Microsoft.Authorization/roleAssignments/write" {
		t.Errorf("azure operationName.value alınmalı: %q", evs[0].EventType)
	}
	if evs[0].Severity != "INFO" {
		t.Errorf("başarılı olay INFO: %q", evs[0].Severity)
	}
}

func TestConnectorRegistryIntegration(t *testing.T) {
	reg := connector.NewRegistry()
	if err := reg.Register(NewCEFConnector("cef1", SlicePuller(nil))); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(NewCloudConnector("gcp1", "gcp", SlicePuller(nil))); err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 2 {
		t.Fatalf("2 bağlayıcı kayıtlı olmalı")
	}
}

func TestHealthUnconfigured(t *testing.T) {
	c := &LogConnector{ConnName: "x"}
	if c.Health() == nil {
		t.Error("puller/normalizer yoksa Health hata dönmeli")
	}
}

func TestBuildFromConfig(t *testing.T) {
	for _, tc := range []struct {
		fmtName, kind string
	}{
		{"syslog", "network"}, {"cef", "siem"}, {"winevent", "identity"}, {"cloud", "cloud"},
	} {
		c, err := Build(SourceConfig{Name: "c-" + tc.fmtName, Format: tc.fmtName, Source: "x.log"})
		if err != nil {
			t.Fatalf("%s Build hatası: %v", tc.fmtName, err)
		}
		if c.Kind() != tc.kind {
			t.Errorf("%s kind=%q, beklenen %q", tc.fmtName, c.Kind(), tc.kind)
		}
	}
	// bilinmeyen format + boş kaynak → hata
	if _, err := Build(SourceConfig{Name: "x", Format: "bogus", Source: "s"}); err == nil {
		t.Error("bilinmeyen format hata dönmeli")
	}
	if _, err := Build(SourceConfig{Name: "x", Format: "syslog"}); err == nil {
		t.Error("boş kaynak hata dönmeli")
	}
}

func TestBuildAll(t *testing.T) {
	reg, err := BuildAll([]SourceConfig{
		{Name: "a", Format: "cef", Source: "a.log"},
		{Name: "b", Format: "cloud", Provider: "aws", Source: "b.json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 2 {
		t.Fatalf("2 bağlayıcı kayıtlı olmalı, %d", len(reg.List()))
	}
	// yinelenen ad → hata
	if _, err := BuildAll([]SourceConfig{{Name: "a", Format: "cef", Source: "1"}, {Name: "a", Format: "cef", Source: "2"}}); err == nil {
		t.Error("yinelenen ad hata dönmeli")
	}
}

func TestIntervalDefault(t *testing.T) {
	if got := (SourceConfig{}).Interval(); got != 60*time.Second {
		t.Errorf("varsayılan aralık 60sn olmalı, %v", got)
	}
	if got := (SourceConfig{IntervalSec: 5}).Interval(); got != 5*time.Second {
		t.Errorf("aralık 5sn olmalı, %v", got)
	}
}
