package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	kutv1 "kut.corp/suite/gen/kut/v1"
)

// errTenantDevices, TenantForDevice'ı hata döndüren bir kayıt sahtesidir.
type errTenantDevices struct{ *fakeDevices }

func (errTenantDevices) TenantForDevice(context.Context, string) (string, error) {
	return "", errors.New("db down")
}

func hb(t *testing.T, h *AgentHandler) {
	t.Helper()
	if _, err := h.Heartbeat(peerCtx("dev-1"), &kutv1.HeartbeatRequest{
		Identity: &kutv1.AgentIdentity{AgentVersion: "1.0.0"},
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
}

// heartbeat cihaz-durumu bildirimi CİHAZIN kiracısına atfedilir; sunucu varsayılan
// kiracısına ("default") DEĞİL.
func TestHeartbeatPublishesUnderDeviceTenant(t *testing.T) {
	adm := &tenantAdmin{}
	h := newTestHandler(&fakeDevices{tenant: "b"}, &fakeEvents{}, &fakeUpdates{})
	h.SetAdminNotifier(adm)
	h.SetTenant("default") // sunucu varsayılanı; "b" cihazı bunun altında yayınlanmamalı
	hb(t, h)
	if len(adm.devTenants) != 1 || adm.devTenants[0] != "b" {
		t.Fatalf("bildirim cihaz kiracısı 'b' ile yayınlanmalı: %+v", adm.devTenants)
	}
}

// Kayıtsız (legacy) cihaz: zorlama kapalıyken sunucu varsayılanı; zorlama AÇIKKEN yayınlanmaz
// (fail-closed); kiracı arama hatasında da yayınlanmaz ve heartbeat yine başarılı olur.
func TestHeartbeatNoticeTenantFailClosed(t *testing.T) {
	// Zorlama kapalı + kiracısız cihaz → sunucu varsayılanı.
	adm := &tenantAdmin{}
	h := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h.SetAdminNotifier(adm)
	h.SetTenant("deploy")
	hb(t, h)
	if len(adm.devTenants) != 1 || adm.devTenants[0] != "deploy" {
		t.Fatalf("legacy cihaz sunucu varsayılanına düşmeli: %+v", adm.devTenants)
	}

	// Zorlama açık + kiracısız cihaz → yayın YOK.
	adm2 := &tenantAdmin{}
	h2 := newTestHandler(&fakeDevices{}, &fakeEvents{}, &fakeUpdates{})
	h2.SetAdminNotifier(adm2)
	h2.SetTenant("deploy")
	h2.SetTenantEnforce(true)
	hb(t, h2)
	if len(adm2.devTenants) != 0 {
		t.Fatalf("enforce açıkken kiracısız cihaz bildirimi yayınlanmamalı: %+v", adm2.devTenants)
	}

	// Kiracı arama hatası → yayın YOK, heartbeat başarılı.
	adm3 := &tenantAdmin{}
	h3 := newTestHandler(errTenantDevices{&fakeDevices{}}, &fakeEvents{}, &fakeUpdates{})
	h3.SetAdminNotifier(adm3)
	h3.SetTenant("deploy")
	hb(t, h3)
	if len(adm3.devTenants) != 0 {
		t.Fatalf("arama hatasında bildirim yayınlanmamalı: %+v", adm3.devTenants)
	}
}

// otomatik karantina sonrası cihaz-durumu bildirimi de cihazın kiracısına atfedilir.
func TestAutoQuarantineNoticeUsesDeviceTenant(t *testing.T) {
	adm := &tenantAdmin{}
	h := newTestHandler(&fakeDevices{tenant: "b"}, &fakeEvents{}, &fakeUpdates{})
	h.SetAlerter(&fakeAlerter{})
	h.SetAdminNotifier(adm)
	h.SetAutoResponder(&fakeResponder{})
	h.SetTenant("default")
	stream := &fakeStream{
		ctx: peerCtx("dev-1"),
		batches: []*kutv1.EventBatch{{Events: []*kutv1.Event{{
			Sequence: 1, Severity: kutv1.Severity_SEVERITY_CRITICAL, Message: "kurcalama",
			OccurredAt: timestamppb.New(time.Now()),
		}}}},
	}
	if err := h.ReportEvents(stream); err != nil {
		t.Fatal(err)
	}
	if len(adm.devTenants) != 1 || adm.devTenants[0] != "b" {
		t.Fatalf("karantina bildirimi cihaz kiracısıyla yayınlanmalı: %+v", adm.devTenants)
	}
}
