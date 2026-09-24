package telemetryschema

import (
	"encoding/json"
	"testing"
	"time"

	"kut.corp/suite/server/internal/model"
)

var testProduct = Product{Name: "Suite", VendorName: "KUT", Version: "1.0.0"}

func sampleEvent() model.Event {
	return model.Event{
		Sequence:      42,
		Category:      "malware",
		Severity:      "HIGH",
		Message:       "suspicious process spawned",
		OccurredAt:    time.Unix(1_700_000_000, 0).UTC(),
		TenantID:      "t1",
		DeviceID:      "pc-01",
		Source:        "endpoint",
		EventType:     "PROCESS_CREATE",
		Confidence:    0.8,
		CorrelationID: "cor_abc",
		ParentEventID: "evt_parent",
		Details:       `{"pid":1234}`,
	}
}

func TestToOCSFCoreMapping(t *testing.T) {
	e := sampleEvent()
	o := ToOCSF(e, testProduct)

	if o.CategoryUID != 2 || o.ClassUID != 2004 || o.TypeUID != 200401 {
		t.Errorf("OCSF sınıflandırma yanlış: cat=%d class=%d type=%d", o.CategoryUID, o.ClassUID, o.TypeUID)
	}
	if o.SeverityID != 4 || o.Severity != "High" {
		t.Errorf("HIGH → severity_id 4/High bekleniyordu: %d/%s", o.SeverityID, o.Severity)
	}
	if o.Time != e.OccurredAt.UnixMilli() {
		t.Errorf("time epoch-ms olmalı: %d", o.Time)
	}
	if o.Metadata.Version != OCSFSchemaVersion || o.Metadata.Product.VendorName != "KUT" {
		t.Errorf("metadata yanlış: %+v", o.Metadata)
	}
	if o.Device == nil || o.Device.UID != "pc-01" {
		t.Errorf("device.uid device_id'den gelmeli: %+v", o.Device)
	}
	if o.ConfidenceScore == nil || *o.ConfidenceScore != 80 {
		t.Errorf("confidence 0.8 → confidence_score 80 olmalı: %v", o.ConfidenceScore)
	}
	if len(o.FindingInfo.Types) != 1 || o.FindingInfo.Types[0] != "PROCESS_CREATE" {
		t.Errorf("finding_info.types event_type taşımalı: %+v", o.FindingInfo.Types)
	}
}

// TestToOCSFPreservesCanonicalID, OCSF çıktısının kanonik içerik-adresli EventID'yi
// koruduğunu (metadata.uid == finding_info.uid == EventID) ve çağıranın kopyasını
// DEĞİŞTİRMEDİĞİNİ doğrular — OCSF çıktısı yinelenebilir/dedup-dostu kalır.
func TestToOCSFPreservesCanonicalID(t *testing.T) {
	e := sampleEvent() // EventID boş
	o := ToOCSF(e, testProduct)
	if o.Metadata.UID == "" || o.Metadata.UID != o.FindingInfo.UID {
		t.Fatalf("metadata.uid == finding_info.uid (kanonik id) olmalı: %q vs %q", o.Metadata.UID, o.FindingInfo.UID)
	}
	if e.EventID != "" {
		t.Errorf("çağıranın kopyası mutasyona uğramamalı (EventID hâlâ boş olmalı): %q", e.EventID)
	}
	// Aynı olay → aynı OCSF uid (kararlılık).
	o2 := ToOCSF(sampleEvent(), testProduct)
	if o2.Metadata.UID != o.Metadata.UID {
		t.Errorf("aynı olay aynı OCSF uid vermeli: %q != %q", o2.Metadata.UID, o.Metadata.UID)
	}
}

func TestToOCSFUnmappedIsLossless(t *testing.T) {
	o := ToOCSF(sampleEvent(), testProduct)
	um := o.Unmapped
	if um == nil {
		t.Fatal("kanonik ek alanlar unmapped altında korunmalı")
	}
	if um["source"] != "endpoint" || um["tenant_id"] != "t1" || um["correlation_id"] != "cor_abc" ||
		um["parent_event_id"] != "evt_parent" || um["category"] != "malware" || um["details"] != `{"pid":1234}` {
		t.Errorf("unmapped alanları eksik/yanlış: %+v", um)
	}
	if seq, _ := um["sequence"].(uint64); seq != 42 {
		t.Errorf("sequence unmapped'te korunmalı: %v", um["sequence"])
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := map[string]struct {
		id   int
		name string
	}{
		"INFO": {1, "Informational"}, "LOW": {2, "Low"}, "MEDIUM": {3, "Medium"},
		"HIGH": {4, "High"}, "CRITICAL": {5, "Critical"}, "WeIrD": {0, "Unknown"}, "": {0, "Unknown"},
	}
	for sev, want := range cases {
		id, name := severityID(sev)
		if id != want.id || name != want.name {
			t.Errorf("%q → %d/%s bekleniyordu, %d/%s alındı", sev, want.id, want.name, id, name)
		}
	}
}

func TestMarshalOCSFValidJSON(t *testing.T) {
	b, err := MarshalOCSF(sampleEvent(), testProduct)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("OCSF çıktısı geçerli JSON olmalı: %v", err)
	}
	if back["class_uid"].(float64) != 2004 || back["type_uid"].(float64) != 200401 {
		t.Errorf("JSON alanları yanlış: %v", back)
	}
}

func TestToOCSFBatch(t *testing.T) {
	if got := ToOCSFBatch(nil, testProduct); got != nil {
		t.Errorf("boş girdi nil dönmeli: %v", got)
	}
	evs := []model.Event{sampleEvent(), {Severity: "LOW", Message: "m2", OccurredAt: time.Unix(1, 0)}}
	out := ToOCSFBatch(evs, testProduct)
	if len(out) != 2 || out[0].SeverityID != 4 || out[1].SeverityID != 2 {
		t.Errorf("batch eşlemesi yanlış: %+v", out)
	}
	if out[0].Metadata.UID == out[1].Metadata.UID {
		t.Error("farklı olaylar farklı uid vermeli")
	}
}
