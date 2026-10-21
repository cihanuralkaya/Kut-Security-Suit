package adminapi

// agentsec.go — Agentic Threat Defense (aisec) uçları. Agent Causality Graph artık kiracı
// BAŞINA bölümlüdür (Z5-02 / Z4a-05): her okuma/yazma, SUNUCU-TARAFI çözülmüş kiracının
// bölümüne gider. Kiracıya bağlı çağıran yalnız kendi bölümünü okur/yazar; istekteki
// tenant parametresi/başlığı yok sayılır. Platform admini tüm bölümleri açık "tenant"
// filtresiyle ya da filtresiz okuyabilir; yazımı açık "tenant" ile bir kiracı bölümüne,
// filtresizse platform ("") bölümüne yapar. İmzalı telemetri bölümü, doğrulayıcının
// (anahtar kaydı) bağladığı kiracıdır.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/aisec"
	"kut.corp/suite/server/internal/aisecnorm"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/model"
)

// İstek başına gözlem tavanı (gövde zaten 1 MiB ile sınırlı; bu, graf kilidini tutma süresini
// ve tavan-doldurma hızını da sınırlar).
const (
	maxAgentSecNodesPerReq = 1000
	maxAgentSecEdgesPerReq = 2000
)

// agentObservation, hem oturumlu ingest hem imzalı telemetri yükünün ortak şemasıdır.
type agentObservation struct {
	Nodes []struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Trust string `json:"trust"`
	} `json:"nodes"`
	Edges []struct {
		Type string `json:"type"`
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"edges"`
}

// errObsTooLarge / errObsBadID, gözlem doğrulama hatalarıdır.
var (
	errObsTooLarge = errors.New("gözlem sayısı istek başına sınırı aşıyor")
	errObsBadID    = errors.New("düğüm kimliği çok uzun")
)

// validate, gözlemi UYGULAMADAN ÖNCE sınırlarını doğrular (ya hep ya hiç: kısmi uygulama yok).
func (o *agentObservation) validate() error {
	if len(o.Nodes) > maxAgentSecNodesPerReq || len(o.Edges) > maxAgentSecEdgesPerReq {
		return errObsTooLarge
	}
	for _, n := range o.Nodes {
		if len(n.ID) > aisec.MaxIDLen {
			return errObsBadID
		}
	}
	for _, e := range o.Edges {
		if len(e.From) > aisec.MaxIDLen || len(e.To) > aisec.MaxIDLen {
			return errObsBadID
		}
	}
	return nil
}

// applyObservation, doğrulanmış gözlemi kiracı bölümüne işler. Hata (bölüm tavanı) iletilir;
// düşen gözlemler sayılır.
func (s *Server) applyObservation(tenantPart string, o *agentObservation) error {
	var firstErr error
	note := func(err error) {
		if err != nil {
			metrics.AddAgentSecDropped(1)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, n := range o.Nodes {
		note(s.agentSec.ObserveNode(tenantPart, n.ID, aisec.NodeKind(n.Kind), aisec.ParseTrust(n.Trust)))
	}
	for _, e := range o.Edges {
		switch e.Type {
		case "read":
			note(s.agentSec.ObserveRead(tenantPart, e.From, e.To))
		case "write":
			note(s.agentSec.ObserveWrite(tenantPart, e.From, e.To))
		case "delegate":
			note(s.agentSec.ObserveDelegate(tenantPart, e.From, e.To))
		case "influence":
			note(s.agentSec.ObserveInfluence(tenantPart, e.From, e.To))
		}
	}
	return firstErr
}

// writeObsErr, gözlem doğrulama/uygulama hatasını HTTP yanıtına çevirir.
func writeObsErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errObsTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, "gözlem sayısı istek başına sınırı aşıyor")
	case errors.Is(err, errObsBadID), errors.Is(err, aisec.ErrIDTooLong):
		writeErr(w, http.StatusBadRequest, "düğüm kimliği çok uzun")
	case errors.Is(err, aisec.ErrTooManyTenants):
		writeErr(w, http.StatusServiceUnavailable, "agent grafı kiracı sınırı doldu")
	default:
		writeErr(w, http.StatusInternalServerError, "gözlem işlenemedi")
	}
}

// handleAgentSecFindings, agentic tehdit savunmasının exfil bulgularını (Agent Causality
// Graph) salt-okunur döner — YALNIZ çağıranın kiracı bölümü (platform admini: tüm bölümler
// ya da ?tenant= ile tek bölüm). Bulgular DATA'dır (INV-AG-010); enforcement §0 zincirinden
// geçer, bu uç yalnız görünürlük sağlar.
func (s *Server) handleAgentSecFindings(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.agentSec == nil {
		writeErr(w, http.StatusNotFound, "agentic tehdit savunması etkin değil")
		return
	}
	part, all, err := s.readScope(r.Context(), adminID, r.URL.Query().Get("tenant"))
	if respondErr(w, err) {
		return
	}
	var tf []aisec.TenantFinding
	if all {
		tf = s.agentSec.FindingsAll()
	} else {
		for _, f := range s.agentSec.Findings(part) {
			tf = append(tf, aisec.TenantFinding{Tenant: part, ExfilFinding: f})
		}
	}
	out := make([]map[string]any, 0, len(tf))
	for _, x := range tf {
		row := map[string]any{
			"agent_id": x.AgentID, "credential": x.Credential,
			"sink": x.Sink, "trust": x.Trust.String(),
		}
		if x.Tenant != "" {
			row["tenant"] = x.Tenant
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "count": len(out)})
}

// handleAgentSecCanonical, AG exfil bulgularını MEVCUT kanonik olay modeline (model.Event)
// çevirip döner (P0-B). Amaç: agent güvenlik tespitlerini ikinci bir modele değil, dedup
// (§6)/korelasyon (§5)/SIEM ile aynı kanonik hatta oturtmak. Salt-okunur; enforcement
// üretmez (INV-AG-010). Kiracı SUNUCU-TARAFI: kiracıya bağlı admin kendi bölümüne sabitlenir
// (?tenant= YOK SAYILIR — çapraz-kiracı sızıntısını önler); platform admini isteğe bağlı
// ?tenant= ile bölüm seçer (sınırda doğrulanır, Z4b-08), filtresizse her bulgu kendi
// bölümünün kiracısıyla atıflanır.
func (s *Server) handleAgentSecCanonical(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.agentSec == nil {
		writeErr(w, http.StatusNotFound, "agentic tehdit savunması etkin değil")
		return
	}
	part, all, err := s.readScope(r.Context(), adminID, r.URL.Query().Get("tenant"))
	if respondErr(w, err) {
		return
	}
	now := s.now().UTC()
	var evs []model.Event
	if all {
		for i, f := range s.agentSec.FindingsAll() {
			evs = append(evs, aisecnorm.FindingToEvent(f.ExfilFinding, f.Tenant, uint64(i), now))
		}
	} else {
		evs = aisecnorm.FindingsToEvents(s.agentSec.Findings(part), part, 0, now)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": model.EventSchemaVersion,
		"events":         evs,
		"count":          len(evs),
	})
}

// handleAgentSecEvents, agent-davranış gözlemlerini (düğüm + kenar) ingest eder ve Agent
// Causality Graph'ı besler (telemetri kaynağı seam'i). Gözlemler DATA'dır; enforcement
// üretmez (INV-AG-010). Kenar tipleri: read (agent→source), write (agent→sink), delegate
// (delegator→delegatee), influence (from→to). Bilinmeyen trust fail-safe Untrusted'a düşer.
// Yazım SUNUCU-TARAFI çözülmüş kiracı bölümüne gider (Z5-02): kiracılı OPERATOR başka
// kiracının düğüm güvenini ezemez / tavanını dolduramaz.
func (s *Server) handleAgentSecEvents(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.agentSec == nil {
		writeErr(w, http.StatusNotFound, "agentic tehdit savunması etkin değil")
		return
	}
	// Bu uç DURUM-DEĞİŞTİRİR (ObserveNode bir düğümün güvenini ÜZERİNE yazar; kenar
	// ekler) → salt-okuma bir VIEWER sahte exfil zinciri üretemesin ya da gerçek bulguyu
	// bastıramasın diye OPERATOR+ gerekir (diğer mutasyon yollarıyla tutarlı; SEC).
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	part, all, err := s.readScope(r.Context(), adminID, r.URL.Query().Get("tenant"))
	if respondErr(w, err) {
		return
	}
	if all {
		part = "" // platform admini, kiracı belirtmeden: platform bölümü
	}
	var req agentObservation
	if !decode(w, r, &req) {
		return
	}
	if verr := req.validate(); verr != nil {
		writeObsErr(w, verr)
		return
	}
	if aerr := s.applyObservation(part, &req); aerr != nil {
		writeObsErr(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": len(req.Nodes), "edges": len(req.Edges)})
}

// handleAgentSecTelemetry, KRİPTOGRAFİK İMZALI agent telemetrisini alır (P0-A). Session
// gerektirmez; kimlik ed25519 imzayla doğrulanır. TrustVerifier fail-closed'dır: imza/
// tenant/sequence/replay/tazelik kontrolü geçmezse 403 (reason'lı) döner ve graf
// BESLENMEZ. Kabul edilirse payload (nodes/edges), DOĞRULANMIŞ agent kimliğinin kayıtlı
// kiracı bölümüne işlenir (bölüm = anahtar kaydındaki kiracı; aynı normalizasyon).
func (s *Server) handleAgentSecTelemetry(w http.ResponseWriter, r *http.Request) {
	if s.agentTrust == nil || s.agentSec == nil {
		writeErr(w, http.StatusNotFound, "agent telemetri etkin değil")
		return
	}
	var wire struct {
		AgentID   string    `json:"agent_id"`
		TenantID  string    `json:"tenant_id"`
		Sequence  uint64    `json:"sequence"`
		Timestamp time.Time `json:"timestamp"`
		Nonce     string    `json:"nonce"`
		Payload   []byte    `json:"payload"`   // kanonik gözlem (base64 JSON)
		Signature []byte    `json:"signature"` // ed25519 (base64)
	}
	if !decode(w, r, &wire) {
		return
	}
	obs := aisec.SignedObservation{
		AgentID: wire.AgentID, TenantID: wire.TenantID, Sequence: wire.Sequence,
		Timestamp: wire.Timestamp, Nonce: wire.Nonce, Payload: wire.Payload, Signature: wire.Signature,
	}
	if err := s.agentTrust.Verify(obs); err != nil {
		writeErr(w, http.StatusForbidden, "telemetri reddedildi: "+err.Error())
		return
	}
	var p agentObservation
	if json.Unmarshal(wire.Payload, &p) != nil {
		writeErr(w, http.StatusBadRequest, "geçersiz payload")
		return
	}
	if verr := p.validate(); verr != nil {
		writeObsErr(w, verr)
		return
	}
	// Verify, wire.TenantID'nin anahtar kaydındaki kiracıyla (normTenant) eşleştiğini kanıtladı;
	// bölüm anahtarı aynı normalizasyondur — istemcinin başka bir bölümü seçmesi mümkün değil.
	part := strings.ToLower(strings.TrimSpace(wire.TenantID))
	if aerr := s.applyObservation(part, &p); aerr != nil {
		writeObsErr(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "nodes": len(p.Nodes), "edges": len(p.Edges)})
}
