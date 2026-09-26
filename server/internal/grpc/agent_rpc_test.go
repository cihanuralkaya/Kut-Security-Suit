package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	kutv1 "kut.corp/suite/gen/kut/v1"
)

// newTestHandler, sahte bağımlılıklarla ve sabit saatle bir AgentHandler kurar.
func newTestHandler(devices DeviceRegistry, events EventSink, updates UpdateProvider) *AgentHandler {
	h := NewAgentHandler(devices, events, nil, updates, nil)
	h.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	return h
}

// ---- Heartbeat ----

func TestHeartbeatUnauthenticated(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	_, err := h.Heartbeat(context.Background(), &kutv1.HeartbeatRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("peer yokken Unauthenticated beklenirdi, dönen: %v", err)
	}
}

func TestHeartbeatBinaryTamper(t *testing.T) {
	dev := &fakeDevices{tampered: true}
	ev := &fakeEvents{}
	admin := &fakeAdmin{}
	alerter := &fakeAlerter{}
	h := newTestHandler(dev, ev, &fakeUpdates{})
	h.SetAdminNotifier(admin)
	h.SetAlerter(alerter)

	_, err := h.Heartbeat(peerCtx("dev-1"), &kutv1.HeartbeatRequest{
		Identity:   &kutv1.AgentIdentity{AgentVersion: "1.0.0"},
		BinaryHash: "deadbeef",
	})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(ev.saved) != 1 || len(ev.saved[0]) != 1 {
		t.Fatalf("kurcalama için 1 öz-tasdik olayı kaydedilmeliydi: %+v", ev.saved)
	}
	got := ev.saved[0][0]
	if got.Severity != "CRITICAL" || got.Category != "SECURITY" {
		t.Errorf("kurcalama olayı CRITICAL/SECURITY olmalı: %+v", got)
	}
	alerts := alerter.all()
	if len(alerts) != 1 || alerts[0].TechniqueID != "T1554" {
		t.Errorf("kurcalama uyarısı T1554 taşımalı: %+v", alerts)
	}
	if dev.recHash != "deadbeef" {
		t.Errorf("RecordAgentBinary hash yanlış: %q", dev.recHash)
	}
}

func TestHeartbeatAckAndResults(t *testing.T) {
	dev := &fakeDevices{}
	h := newTestHandler(dev, &fakeEvents{}, &fakeUpdates{})

	_, err := h.Heartbeat(peerCtx("dev-1"), &kutv1.HeartbeatRequest{
		AckedCommandIds: []string{"c1", "c2"},
		CommandResults: []*kutv1.CommandResult{
			{CommandId: "c1", CommandType: kutv1.Command_COMMAND_TYPE_QUARANTINE, Status: kutv1.CommandStatus_COMMAND_STATUS_SUCCEEDED},
			{CommandId: "c3", CommandType: kutv1.Command_COMMAND_TYPE_RESTART, Status: kutv1.CommandStatus_COMMAND_STATUS_FAILED},
		},
	})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(dev.acked) != 2 || dev.acked[0] != "c1" {
		t.Errorf("acked komutlar yanlış: %+v", dev.acked)
	}
	if len(dev.outcomes) != 2 {
		t.Fatalf("2 komut sonucu beklenirdi: %+v", dev.outcomes)
	}
	if dev.outcomes[0].Type != "QUARANTINE" || !dev.outcomes[0].OK {
		t.Errorf("ilk sonuç QUARANTINE/OK olmalı: %+v", dev.outcomes[0])
	}
	if dev.outcomes[1].Type != "RESTART" || dev.outcomes[1].OK {
		t.Errorf("ikinci sonuç RESTART/!OK olmalı: %+v", dev.outcomes[1])
	}
}

func TestHeartbeatPolicyUpdateAvailable(t *testing.T) {
	// Sunucu sürümü ajanınkinden farklı → true.
	h := newTestHandler(&fakeDevices{policyVer: "v2"}, &fakeEvents{}, &fakeUpdates{})
	resp, err := h.Heartbeat(peerCtx("dev-1"), &kutv1.HeartbeatRequest{CurrentPolicyVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetPolicyUpdateAvailable() {
		t.Error("farklı sürümde PolicyUpdateAvailable true olmalı")
	}
	// Aynı sürüm → false.
	h2 := newTestHandler(&fakeDevices{policyVer: "v1"}, &fakeEvents{}, &fakeUpdates{})
	resp2, err := h2.Heartbeat(peerCtx("dev-1"), &kutv1.HeartbeatRequest{CurrentPolicyVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp2.GetPolicyUpdateAvailable() {
		t.Error("aynı sürümde PolicyUpdateAvailable false olmalı")
	}
}

func TestHeartbeatTouchError(t *testing.T) {
	h := newTestHandler(&fakeDevices{touchErr: errors.New("db down")}, &fakeEvents{}, &fakeUpdates{})
	_, err := h.Heartbeat(peerCtx("dev-1"), &kutv1.HeartbeatRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("TouchHeartbeat hatası → Internal beklenirdi, dönen: %v", err)
	}
}

func TestHeartbeatPendingError(t *testing.T) {
	h := newTestHandler(&fakeDevices{pendErr: errors.New("boom")}, &fakeEvents{}, &fakeUpdates{})
	_, err := h.Heartbeat(peerCtx("dev-1"), &kutv1.HeartbeatRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("PendingCommands hatası → Internal beklenirdi, dönen: %v", err)
	}
}

// ---- ReportEvents ----

func TestReportEventsUnauthenticated(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	err := h.ReportEvents(&fakeStream{ctx: context.Background()})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("peer yokken Unauthenticated beklenirdi, dönen: %v", err)
	}
}

func TestReportEventsEOFReturnsLastAccepted(t *testing.T) {
	ev := &fakeEvents{last: 42}
	h := newTestHandler(&fakeDevices{}, ev, &fakeUpdates{})
	h.SetAlerter(&fakeAlerter{})
	stream := &fakeStream{
		ctx: peerCtx("dev-1"),
		batches: []*kutv1.EventBatch{
			{Events: []*kutv1.Event{{Sequence: 42, Message: "hi", OccurredAt: timestamppb.New(time.Now())}}},
		},
	}
	if err := h.ReportEvents(stream); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if stream.ack == nil || stream.ack.GetLastAcceptedSequence() != 42 {
		t.Fatalf("EOF'ta lastAccepted=42 dönmeliydi: %+v", stream.ack)
	}
}

func TestReportEventsRecvError(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	sentinel := errors.New("stream broken")
	stream := &fakeStream{ctx: peerCtx("dev-1"), recvErr: sentinel}
	if err := h.ReportEvents(stream); !errors.Is(err, sentinel) {
		t.Fatalf("EOF-olmayan Recv hatası olduğu gibi dönmeli, dönen: %v", err)
	}
}

func TestReportEventsSaveError(t *testing.T) {
	ev := &fakeEvents{err: errors.New("write failed")}
	h := newTestHandler(&fakeDevices{}, ev, &fakeUpdates{})
	h.SetAlerter(&fakeAlerter{})
	stream := &fakeStream{
		ctx: peerCtx("dev-1"),
		batches: []*kutv1.EventBatch{
			{Events: []*kutv1.Event{{Sequence: 1, Message: "x", OccurredAt: timestamppb.New(time.Now())}}},
		},
	}
	err := h.ReportEvents(stream)
	if status.Code(err) != codes.Internal {
		t.Fatalf("SaveEvents hatası → Internal beklenirdi, dönen: %v", err)
	}
}

func TestReportEventsAutoQuarantineOnce(t *testing.T) {
	resp := &fakeResponder{}
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetAlerter(&fakeAlerter{})
	h.SetAutoResponder(resp)

	crit := func(seq uint64) *kutv1.EventBatch {
		return &kutv1.EventBatch{Events: []*kutv1.Event{{
			Sequence:   seq,
			Severity:   kutv1.Severity_SEVERITY_CRITICAL,
			Message:    "kurcalama",
			OccurredAt: timestamppb.New(time.Now()),
		}}}
	}
	stream := &fakeStream{
		ctx:     peerCtx("dev-1"),
		batches: []*kutv1.EventBatch{crit(1), crit(2)}, // iki kritik batch
	}
	if err := h.ReportEvents(stream); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if resp.calls != 1 {
		t.Fatalf("otomatik karantina akış başına yalnız bir kez tetiklenmeli, çağrı=%d", resp.calls)
	}
}

// ---- CheckUpdate ----

func TestCheckUpdateUnauthenticated(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	_, err := h.CheckUpdate(context.Background(), &kutv1.UpdateCheckRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("peer yokken Unauthenticated beklenirdi, dönen: %v", err)
	}
}

func TestCheckUpdateNil(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{m: nil})
	m, err := h.CheckUpdate(peerCtx("dev-1"), &kutv1.UpdateCheckRequest{Identity: &kutv1.AgentIdentity{}})
	if err != nil {
		t.Fatal(err)
	}
	if m.GetUpdateAvailable() {
		t.Error("güncelleme yokken UpdateAvailable false olmalı")
	}
}

func TestCheckUpdateNotInCohort(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{
		m: &kutv1.UpdateManifest{UpdateAvailable: true, TargetVersion: "2.0.0", RolloutPercent: 0},
	})
	m, err := h.CheckUpdate(peerCtx("dev-1"), &kutv1.UpdateCheckRequest{Identity: &kutv1.AgentIdentity{}})
	if err != nil {
		t.Fatal(err)
	}
	if m.GetUpdateAvailable() {
		t.Error("rollout kohortunda değilken UpdateAvailable false olmalı")
	}
}

func TestCheckUpdateSuccess(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{
		m: &kutv1.UpdateManifest{UpdateAvailable: true, TargetVersion: "2.0.0", RolloutPercent: 100},
	})
	m, err := h.CheckUpdate(peerCtx("dev-1"), &kutv1.UpdateCheckRequest{Identity: &kutv1.AgentIdentity{}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.GetUpdateAvailable() || m.GetTargetVersion() != "2.0.0" {
		t.Errorf("kohorttaki cihaza manifesto dönmeliydi: %+v", m)
	}
}

func TestCheckUpdateError(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{err: errors.New("db")})
	_, err := h.CheckUpdate(peerCtx("dev-1"), &kutv1.UpdateCheckRequest{Identity: &kutv1.AgentIdentity{}})
	if status.Code(err) != codes.Internal {
		t.Fatalf("LatestUpdate hatası → Internal beklenirdi, dönen: %v", err)
	}
}

// ---- UploadArtifact ----

func TestUploadArtifactUnauthenticated(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetArtifactSink(&fakeArtifacts{})
	_, err := h.UploadArtifact(context.Background(), &kutv1.UploadArtifactRequest{Content: []byte("x")})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("peer yokken Unauthenticated beklenirdi, dönen: %v", err)
	}
}

func TestUploadArtifactEmpty(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetArtifactSink(&fakeArtifacts{})
	_, err := h.UploadArtifact(peerCtx("dev-1"), &kutv1.UploadArtifactRequest{Content: nil})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("boş içerik → InvalidArgument beklenirdi, dönen: %v", err)
	}
}

func TestUploadArtifactTooLarge(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetArtifactSink(&fakeArtifacts{})
	big := make([]byte, maxArtifactBytes+1)
	_, err := h.UploadArtifact(peerCtx("dev-1"), &kutv1.UploadArtifactRequest{Content: big})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf(">3MiB → InvalidArgument beklenirdi, dönen: %v", err)
	}
}

func TestUploadArtifactSHAMismatch(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetArtifactSink(&fakeArtifacts{})
	_, err := h.UploadArtifact(peerCtx("dev-1"), &kutv1.UploadArtifactRequest{
		Content: []byte("hello"), Sha256: "yanlis-hash",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("SHA uyuşmazlığı → InvalidArgument beklenirdi, dönen: %v", err)
	}
}

func TestUploadArtifactSaveError(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetArtifactSink(&fakeArtifacts{err: errors.New("disk full")})
	_, err := h.UploadArtifact(peerCtx("dev-1"), &kutv1.UploadArtifactRequest{Content: []byte("hello")})
	if status.Code(err) != codes.Internal {
		t.Fatalf("save hatası → Internal beklenirdi, dönen: %v", err)
	}
}

func TestUploadArtifactSuccess(t *testing.T) {
	sink := &fakeArtifacts{}
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetArtifactSink(sink)
	content := []byte("forensic-file")
	sum := sha256.Sum256(content)
	resp, err := h.UploadArtifact(peerCtx("dev-1"), &kutv1.UploadArtifactRequest{
		CommandId: "cmd-1", Path: "/tmp/x", Content: content, Sha256: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if !resp.GetOk() {
		t.Error("başarılı yüklemede Ok true olmalı")
	}
	if sink.saved != 1 || sink.lastSHA != hex.EncodeToString(sum[:]) {
		t.Errorf("artefakt beklenen SHA ile kaydedilmeliydi: saved=%d sha=%q", sink.saved, sink.lastSHA)
	}
}

// ---- Pure helpers ----

func TestCommandTypeName(t *testing.T) {
	cases := []struct {
		in   kutv1.Command_CommandType
		want string
	}{
		{kutv1.Command_COMMAND_TYPE_QUARANTINE, "QUARANTINE"},
		{kutv1.Command_COMMAND_TYPE_UNQUARANTINE, "UNQUARANTINE"},
		{kutv1.Command_COMMAND_TYPE_LOCK, "LOCK"},
		{kutv1.Command_COMMAND_TYPE_RESTART, "RESTART"},
		{kutv1.Command_COMMAND_TYPE_WIPE, "WIPE"},
		{kutv1.Command_COMMAND_TYPE_COLLECT_FILE, ""},
		{kutv1.Command_COMMAND_TYPE_UNSPECIFIED, ""},
	}
	for _, c := range cases {
		if got := commandTypeName(c.in); got != c.want {
			t.Errorf("commandTypeName(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDBCategory(t *testing.T) {
	cases := []struct {
		in   kutv1.EventCategory
		want string
	}{
		{kutv1.EventCategory_EVENT_CATEGORY_SECURITY, "SECURITY"},
		{kutv1.EventCategory_EVENT_CATEGORY_SYSTEM, "SYSTEM"},
		{kutv1.EventCategory_EVENT_CATEGORY_PROCESS, "PROCESS"},
		{kutv1.EventCategory_EVENT_CATEGORY_UNSPECIFIED, "SYSTEM"}, // belirsiz → SYSTEM
	}
	for _, c := range cases {
		if got := dbCategory(c.in); got != c.want {
			t.Errorf("dbCategory(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDBSeverity(t *testing.T) {
	cases := []struct {
		in   kutv1.Severity
		want string
	}{
		{kutv1.Severity_SEVERITY_CRITICAL, "CRITICAL"},
		{kutv1.Severity_SEVERITY_INFO, "INFO"},
		{kutv1.Severity_SEVERITY_HIGH, "HIGH"},
		{kutv1.Severity_SEVERITY_UNSPECIFIED, "INFO"}, // belirsiz → INFO
	}
	for _, c := range cases {
		if got := dbSeverity(c.in); got != c.want {
			t.Errorf("dbSeverity(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDetailsJSON(t *testing.T) {
	if got := detailsJSON(nil); got != "" {
		t.Errorf("nil details boş string dönmeli, %q", got)
	}
	st, err := structpb.NewStruct(map[string]any{"ip": "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	got := detailsJSON(st)
	if got == "" || got == "{}" {
		t.Errorf("dolu struct JSON üretmeli, %q", got)
	}
}

// ReportEvents, cihazın SUNUCU-TARAFI kiracısını (TenantForDevice) çözüp olaya atamalı ve bu
// per-device kiracı, sunucu-varsayılan kiracıyı EZMELİ (çok-tenant izolasyonu).
func TestReportEventsBindsPerDeviceTenant(t *testing.T) {
	adm := &tenantAdmin{}
	ev := &fakeEvents{}
	h := newTestHandler(&fakeDevices{tenant: "acme"}, ev, &fakeUpdates{})
	h.SetAlerter(&fakeAlerter{})
	h.SetAdminNotifier(adm)
	h.SetTenant("server-default") // per-device "acme" bunu ezmeli
	stream := &fakeStream{
		ctx: peerCtx("dev-1"),
		batches: []*kutv1.EventBatch{
			{Events: []*kutv1.Event{{Sequence: 1, Message: "x", OccurredAt: timestamppb.New(time.Now())}}},
		},
	}
	if err := h.ReportEvents(stream); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if adm.lastTenant != "acme" {
		t.Fatalf("per-device kiracı 'acme' beklenir (server-default'u ezmeli), alınan %q", adm.lastTenant)
	}
	// Kaydedilen olay da kiracıyı taşımalı (event_logs.tenant_id — çekirdek depo tenant-atıflı).
	if len(ev.saved) == 0 || len(ev.saved[0]) == 0 || ev.saved[0][0].TenantID != "acme" {
		t.Fatalf("kaydedilen olay 'acme' kiracısını taşımalı: %+v", ev.saved)
	}
}

// Sıkı çok-tenant: kiracıya bağlı OLMAYAN cihazın olayları reddedilmeli (INV-044 missing→DENY).
func TestReportEventsTenantEnforceRejectsUnbound(t *testing.T) {
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{}) // cihaz kiracısı ""
	h.SetAlerter(&fakeAlerter{})
	h.SetTenantEnforce(true) // h.tenant "" + cihaz kiracısı yok → reddet
	stream := &fakeStream{
		ctx: peerCtx("dev-1"),
		batches: []*kutv1.EventBatch{
			{Events: []*kutv1.Event{{Sequence: 1, Message: "x", OccurredAt: timestamppb.New(time.Now())}}},
		},
	}
	if err := h.ReportEvents(stream); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("kiracısız cihaz FailedPrecondition ile reddedilmeli, alınan: %v", err)
	}
}

// Sıkı çok-tenant AÇIK ama cihazın kiracısı VARSA olaylar kabul edilmeli.
func TestReportEventsTenantEnforceAllowsBound(t *testing.T) {
	ev := &fakeEvents{}
	h := newTestHandler(&fakeDevices{tenant: "acme"}, ev, &fakeUpdates{})
	h.SetAlerter(&fakeAlerter{})
	h.SetTenantEnforce(true)
	stream := &fakeStream{
		ctx: peerCtx("dev-1"),
		batches: []*kutv1.EventBatch{
			{Events: []*kutv1.Event{{Sequence: 1, Message: "x", OccurredAt: timestamppb.New(time.Now())}}},
		},
	}
	if err := h.ReportEvents(stream); err != nil {
		t.Fatalf("kiracıya bağlı cihaz kabul edilmeli: %v", err)
	}
	if len(ev.saved) == 0 || ev.saved[0][0].TenantID != "acme" {
		t.Fatalf("kaydedilen olay 'acme' taşımalı: %+v", ev.saved)
	}
}
