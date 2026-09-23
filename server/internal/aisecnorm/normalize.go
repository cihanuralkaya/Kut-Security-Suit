// Package aisecnorm, Agentic Threat Defense düzleminin (aisec) bulgularını MEVCUT kanonik
// olay modeline (model.Event) dönüştüren köprüdür (roadmap P0-B). AMAÇ: agent güvenlik
// tespitleri için İKİNCİ bir olay modeli icat etmemek — bulgular da kimlik (içerik-adresli
// EventID → dedup §6), korelasyon (§5) ve SIEM dışa aktarımı ile aynı hattan akmalı.
//
// Bu paket saf ve deterministiktir: yalnız aisec (DATA üreteci) + model (nötr domain) import
// eder, hiçbir yürütme/yetki sınır paketine dokunmaz — böylece AG düzleminin gözlem-yalnız
// doğası (INV-AG-010) köprüde de korunur.
package aisecnorm

import (
	"encoding/json"
	"time"

	"kut.corp/suite/server/internal/aisec"
	"kut.corp/suite/server/internal/model"
)

// Kanonik sınıflandırma sabitleri. Tüketiciler (SIEM/console/korelasyon) bunlara göre dallanır.
const (
	// SourceAgentSec, olayın AG telemetri düzleminden geldiğini belirtir.
	SourceAgentSec = "agentsec"
	// EventTypeExfil, "untrusted agent → credential → external sink" zincirinin tipidir.
	EventTypeExfil = "AGENT_EXFIL_CHAIN"
	// CategoryAISec, agent güvenlik olaylarının kategorisidir.
	CategoryAISec = "ai_agent_security"
	// exfilMessage, exfil zincirinin okunur özetidir (dile bağımsız, kararlı → EnsureID stabil).
	exfilMessage = "agent exfiltration chain: untrusted agent read a credential and wrote to an external sink"
)

// severityForTrust, düşmüş ETKİN güveni kanonik severity + güven skoruna eşler. Exfil
// bulguları yalnız Tainted/Untrusted üretir (DetectExfiltration eff<=Untrusted süzer);
// Tainted (etki zincirine girmiş, en düşük güven) daha ağır kabul edilir.
func severityForTrust(t aisec.TrustLevel) (severity string, confidence float64) {
	switch t {
	case aisec.Tainted:
		return "CRITICAL", 0.9
	default: // Untrusted (ve savunmacı olarak diğer her şey)
		return "HIGH", 0.75
	}
}

// FindingToEvent, tek bir exfil bulgusunu kanonik model.Event'e çevirir ve içerik-adresli
// EventID atar (aynı bulgu → aynı kimlik → dedup/replay idempotensi §6/§19). observedAt,
// bulgunun gözlemlendiği andır (created_at'ı DB atar). seq, üretici sırasıdır.
func FindingToEvent(f aisec.ExfilFinding, tenantID string, seq uint64, observedAt time.Time) model.Event {
	sev, conf := severityForTrust(f.Trust)
	details, _ := json.Marshal(map[string]string{
		"agent_id":   f.AgentID,
		"credential": f.Credential,
		"sink":       f.Sink,
		"trust":      f.Trust.String(),
	})
	e := model.Event{
		Sequence:   seq,
		Category:   CategoryAISec,
		Severity:   sev,
		Message:    exfilMessage,
		OccurredAt: observedAt,
		TenantID:   tenantID,
		DeviceID:   f.AgentID, // atıf: zinciri yürüten agent
		Source:     SourceAgentSec,
		EventType:  EventTypeExfil,
		Confidence: conf,
		Details:    string(details),
	}
	e.EnsureID()
	return e
}

// FindingsToEvents, bir bulgu dilimini kanonik olaylara çevirir. Sequence baseSeq'ten
// başlar ve her bulguda artar (kararlı üretici sırası). Boş girdi → nil.
func FindingsToEvents(fs []aisec.ExfilFinding, tenantID string, baseSeq uint64, observedAt time.Time) []model.Event {
	if len(fs) == 0 {
		return nil
	}
	out := make([]model.Event, 0, len(fs))
	for i, f := range fs {
		out = append(out, FindingToEvent(f, tenantID, baseSeq+uint64(i), observedAt))
	}
	return out
}
