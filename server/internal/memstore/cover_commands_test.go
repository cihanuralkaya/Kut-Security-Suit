package memstore

import (
	"context"
	"testing"

	kutv1 "kut.corp/suite/gen/kut/v1"
)

// EnqueueCommand + PendingCommands: kuyruğa eklenen komut teslim edilir ve
// kuyruk temizlenir; ikinci PendingCommands boş döner. commandTypeToProto,
// proto tipe eşlenir.
func TestEnqueueAndPendingCommands(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)

	if err := s.EnqueueCommand(ctx, id, "QUARANTINE", "admin-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueCommand(ctx, id, "RESTART", "admin-1"); err != nil {
		t.Fatal(err)
	}

	pend, err := s.PendingCommands(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(pend) != 2 {
		t.Fatalf("2 bekleyen komut beklenirdi: %d", len(pend))
	}
	if pend[0].Type != kutv1.Command_COMMAND_TYPE_QUARANTINE {
		t.Fatalf("ilk komut QUARANTINE olmalıydı: %v", pend[0].Type)
	}
	if pend[1].Type != kutv1.Command_COMMAND_TYPE_RESTART {
		t.Fatalf("ikinci komut RESTART olmalıydı: %v", pend[1].Type)
	}
	if pend[0].CommandId == "" {
		t.Fatal("komut id atanmalıydı")
	}

	// Teslim sonrası kuyruk temizlenir.
	again, _ := s.PendingCommands(ctx, id)
	if len(again) != 0 {
		t.Fatalf("teslimden sonra kuyruk boş olmalıydı: %d", len(again))
	}
}

// EnqueueCommandParams: params structpb'ye çevrilir; boş params için nil kalır.
func TestEnqueueCommandParams(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)

	if err := s.EnqueueCommandParams(ctx, id, "RUN_SIGNED_SCRIPT", "op", map[string]string{
		"script": "cleanup.ps1", "arg": "--force",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueCommandParams(ctx, id, "LOCK", "op", nil); err != nil {
		t.Fatal(err)
	}

	pend, _ := s.PendingCommands(ctx, id)
	if len(pend) != 2 {
		t.Fatalf("2 komut beklenirdi: %d", len(pend))
	}
	if pend[0].Type != kutv1.Command_COMMAND_TYPE_RUN_SIGNED_SCRIPT {
		t.Fatalf("tip RUN_SIGNED_SCRIPT olmalıydı: %v", pend[0].Type)
	}
	if pend[0].Params == nil {
		t.Fatal("params structpb üretilmeliydi")
	}
	if got := pend[0].Params.Fields["script"].GetStringValue(); got != "cleanup.ps1" {
		t.Fatalf("params script değeri hatalı: %q", got)
	}
	// Boş params → nil.
	if pend[1].Params != nil {
		t.Fatalf("boş params için nil beklenirdi: %v", pend[1].Params)
	}
}

// CommandHistory: teslim edilse de geçmiş korunur; en yeniden eskiye sıralı;
// teslim sonrası deliveredAt işaretlenir; sadece ilgili cihazı döner.
func TestCommandHistory(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)
	other := "dev-other"

	if err := s.EnqueueCommand(ctx, id, "QUARANTINE", "a1"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueCommand(ctx, id, "UNQUARANTINE", "a2"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueCommand(ctx, other, "WIPE", "a3"); err != nil {
		t.Fatal(err)
	}

	// Teslimden önce deliveredAt nil olmalı.
	hist, err := s.CommandHistory(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("id için 2 geçmiş kaydı beklenirdi: %d", len(hist))
	}
	// En yeniden eskiye: ilk sırada UNQUARANTINE.
	if hist[0].Type != "UNQUARANTINE" || hist[1].Type != "QUARANTINE" {
		t.Fatalf("geçmiş en yeniden eskiye sıralı olmalıydı: %q,%q", hist[0].Type, hist[1].Type)
	}
	if hist[0].DeliveredAt != nil {
		t.Fatal("teslimden önce deliveredAt nil olmalıydı")
	}
	if hist[0].IssuedBy != "a2" {
		t.Fatalf("issuedBy hatalı: %q", hist[0].IssuedBy)
	}

	// Teslim et → geçmişte deliveredAt işaretlenir.
	if _, err := s.PendingCommands(ctx, id); err != nil {
		t.Fatal(err)
	}
	hist, _ = s.CommandHistory(ctx, id)
	for _, h := range hist {
		if h.DeliveredAt == nil {
			t.Fatalf("teslimden sonra deliveredAt işaretlenmeliydi: %+v", h)
		}
	}

	// Diğer cihazın geçmişi ayrı.
	oh, _ := s.CommandHistory(ctx, other)
	if len(oh) != 1 || oh[0].Type != "WIPE" {
		t.Fatalf("diğer cihazın geçmişi hatalı: %+v", oh)
	}
}

// commandTypeToProto: tüm bilinen tipler + bilinmeyen → UNSPECIFIED.
func TestCommandTypeToProto(t *testing.T) {
	cases := map[string]kutv1.Command_CommandType{
		"QUARANTINE":          kutv1.Command_COMMAND_TYPE_QUARANTINE,
		"UNQUARANTINE":        kutv1.Command_COMMAND_TYPE_UNQUARANTINE,
		"RUN_SIGNED_SCRIPT":   kutv1.Command_COMMAND_TYPE_RUN_SIGNED_SCRIPT,
		"UNINSTALL":           kutv1.Command_COMMAND_TYPE_UNINSTALL,
		"COLLECT_DIAGNOSTICS": kutv1.Command_COMMAND_TYPE_COLLECT_DIAGNOSTICS,
		"COLLECT_FILE":        kutv1.Command_COMMAND_TYPE_COLLECT_FILE,
		"LOCK":                kutv1.Command_COMMAND_TYPE_LOCK,
		"RESTART":             kutv1.Command_COMMAND_TYPE_RESTART,
		"WIPE":                kutv1.Command_COMMAND_TYPE_WIPE,
		"NONSENSE":            kutv1.Command_COMMAND_TYPE_UNSPECIFIED,
		"":                    kutv1.Command_COMMAND_TYPE_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := commandTypeToProto(in); got != want {
			t.Errorf("commandTypeToProto(%q)=%v, beklenen %v", in, got, want)
		}
	}
}
