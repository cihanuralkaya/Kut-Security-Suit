// Package telemetryschema, KUT'un kanonik olay modelini (model.Event) sektör-standardı
// OCSF (Open Cybersecurity Schema Framework) biçimine eşler (roadmap P1: ortak olay şeması).
// AMAÇ: downstream SIEM/veri-gölü/analitik araçlarının olayları standart bir şemayla
// tüketebilmesi. Eşleme SAF ve deterministiktir: yalnız model (nötr domain) + stdlib import
// eder, hiçbir yürütme/depolama sınırına dokunmaz. Kanonik EventID korunur (finding_info.uid)
// → OCSF çıktısı da içerik-adresli/yinelenebilir kalır ([[aisecnorm]] ile aynı ilke).
package telemetryschema

import (
	"encoding/json"

	"kut.corp/suite/server/internal/model"
)

// OCSF sınıflandırma sabitleri (Detection Finding, Findings kategorisi). type_uid =
// class_uid*100 + activity_id (OCSF kuralı). activity 1 = Create (yeni bulgu).
const (
	OCSFSchemaVersion = "1.1.0"

	categoryUID  = 2 // Findings
	categoryName = "Findings"
	classUID     = 2004 // Detection Finding
	className    = "Detection Finding"
	activityID   = 1 // Create
	activityName = "Create"
	typeUID      = classUID*100 + activityID // 200401
)

// Product, OCSF metadata.product alanıdır (üreten ürün kimliği; denetlenebilirlik).
type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version,omitempty"`
}

// Metadata, OCSF zorunlu metadata nesnesidir. UID, olayın kararlı kaydı (kanonik EventID).
type Metadata struct {
	Version string  `json:"version"` // OCSF şema sürümü
	Product Product `json:"product"`
	UID     string  `json:"uid,omitempty"`
}

// FindingInfo, Detection Finding'in kimlik/başlık bilgisidir (OCSF finding_info).
type FindingInfo struct {
	UID         string   `json:"uid"`
	Title       string   `json:"title"`
	Types       []string `json:"types,omitempty"`
	CreatedTime int64    `json:"created_time,omitempty"` // epoch ms
}

// Device, olayın atfedildiği uç (OCSF device); type_id 0 = Unknown (yanlış tip iddiası yok).
type Device struct {
	UID    string `json:"uid"`
	TypeID int    `json:"type_id"`
}

// Event, OCSF Detection Finding olayıdır (JSON serileştirmesi OCSF-uyumlu alan adlarıyla).
type Event struct {
	CategoryUID     int            `json:"category_uid"`
	CategoryName    string         `json:"category_name"`
	ClassUID        int            `json:"class_uid"`
	ClassName       string         `json:"class_name"`
	TypeUID         int            `json:"type_uid"`
	ActivityID      int            `json:"activity_id"`
	ActivityName    string         `json:"activity_name"`
	Time            int64          `json:"time"` // epoch ms (occurred_at)
	SeverityID      int            `json:"severity_id"`
	Severity        string         `json:"severity"`
	Message         string         `json:"message,omitempty"`
	ConfidenceScore *int           `json:"confidence_score,omitempty"` // 0..100
	Metadata        Metadata       `json:"metadata"`
	FindingInfo     FindingInfo    `json:"finding_info"`
	Device          *Device        `json:"device,omitempty"`
	Unmapped        map[string]any `json:"unmapped,omitempty"` // OCSF'ye birebir oturmayan kanonik alanlar
}

// severityID, KUT severity string'ini OCSF severity_id'ye eşler. OCSF: 0 Unknown, 1
// Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal. Bilinmeyen → 0 (Unknown).
func severityID(sev string) (int, string) {
	switch sev {
	case "INFO", "INFORMATIONAL":
		return 1, "Informational"
	case "LOW":
		return 2, "Low"
	case "MEDIUM":
		return 3, "Medium"
	case "HIGH":
		return 4, "High"
	case "CRITICAL":
		return 5, "Critical"
	default:
		return 0, "Unknown"
	}
}

// ToOCSF, tek bir kanonik olayı OCSF Detection Finding'e eşler. e kopya olarak alınır;
// EventID boşsa içerik-adresli kimlik türetilir (çağıranın kopyası değişmez) ve hem
// metadata.uid hem finding_info.uid'de kullanılır → OCSF çıktısı yinelenebilir/dedup-dostu.
func ToOCSF(e model.Event, product Product) Event {
	id := e.EnsureID() // yerel kopya üzerinde; kararlı içerik-adresli kimlik
	sevID, sevName := severityID(e.Severity)

	title := e.EventType
	if title == "" {
		title = e.Category
	}
	if title == "" {
		title = e.Message
	}

	o := Event{
		CategoryUID: categoryUID, CategoryName: categoryName,
		ClassUID: classUID, ClassName: className,
		TypeUID: typeUID, ActivityID: activityID, ActivityName: activityName,
		Time:       e.OccurredAt.UnixMilli(),
		SeverityID: sevID, Severity: sevName,
		Message: e.Message,
		Metadata: Metadata{
			Version: OCSFSchemaVersion,
			Product: product,
			UID:     id,
		},
		FindingInfo: FindingInfo{
			UID:         id,
			Title:       title,
			CreatedTime: e.OccurredAt.UnixMilli(),
		},
	}
	if e.EventType != "" {
		o.FindingInfo.Types = []string{e.EventType}
	}
	if e.Confidence > 0 {
		cs := int(e.Confidence*100 + 0.5) // 0..1 → 0..100 (yuvarla)
		if cs > 100 {
			cs = 100
		}
		o.ConfidenceScore = &cs
	}
	if e.DeviceID != "" {
		o.Device = &Device{UID: e.DeviceID, TypeID: 0} // 0 = Unknown (tip iddia edilmez)
	}

	// OCSF'ye birinci-sınıf oturmayan kanonik alanlar unmapped altında korunur (kayıpsız).
	um := map[string]any{}
	if e.Source != "" {
		um["source"] = e.Source
	}
	if e.Category != "" {
		um["category"] = e.Category
	}
	if e.TenantID != "" {
		um["tenant_id"] = e.TenantID
	}
	if e.CorrelationID != "" {
		um["correlation_id"] = e.CorrelationID
	}
	if e.ParentEventID != "" {
		um["parent_event_id"] = e.ParentEventID
	}
	if e.Sequence != 0 {
		um["sequence"] = e.Sequence
	}
	if e.Details != "" {
		um["details"] = e.Details
	}
	if len(um) > 0 {
		o.Unmapped = um
	}
	return o
}

// ToOCSFBatch, bir olay dilimini OCSF olaylarına eşler (sıra korunur). Boş → nil.
func ToOCSFBatch(events []model.Event, product Product) []Event {
	if len(events) == 0 {
		return nil
	}
	out := make([]Event, 0, len(events))
	for _, e := range events {
		out = append(out, ToOCSF(e, product))
	}
	return out
}

// MarshalOCSF, bir olayı OCSF JSON'a serileştirir.
func MarshalOCSF(e model.Event, product Product) ([]byte, error) {
	return json.Marshal(ToOCSF(e, product))
}
