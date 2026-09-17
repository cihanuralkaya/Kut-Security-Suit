package adminread

import (
	"context"
	"testing"
	"time"
)

func TestDeviceEvidenceReproducible(t *testing.T) {
	at := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	store := &memStore{artifacts: []ArtifactRow{
		{ID: "art-1", DeviceID: "dev-9", Path: "/tmp/x", SHA256: "deadbeef", Size: 128, CollectedAt: at},
	}}
	svc := NewService(store, newCipher(t))
	ctx := context.Background()

	a, err := svc.DeviceEvidence(ctx, "dev-9")
	if err != nil || len(a) != 1 {
		t.Fatalf("1 delil kaydı beklenir: %v (%d)", err, len(a))
	}
	if !a[0].Verified {
		t.Error("gözetim zinciri doğrulanmalı")
	}
	if a[0].SHA256 != "deadbeef" || len(a[0].Custody) != 1 {
		t.Fatalf("içerik hash + genesis gözetim: %+v", a[0].Evidence)
	}
	// İkinci çağrı AYNI gözetim hash'ini vermeli (yeniden üretilebilir / kararlı).
	b, _ := svc.DeviceEvidence(ctx, "dev-9")
	if b[0].Custody[0].Hash != a[0].Custody[0].Hash {
		t.Errorf("aynı artefakt aynı gözetim hash'ini vermeli (kararlı):\n1: %s\n2: %s",
			a[0].Custody[0].Hash, b[0].Custody[0].Hash)
	}
}

func TestRecordCustodyPersistsAndVerifies(t *testing.T) {
	at := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	store := &memStore{artifacts: []ArtifactRow{
		{ID: "art-1", DeviceID: "dev-9", Path: "/tmp/x", SHA256: "deadbeef", Size: 128, CollectedAt: at},
	}}
	svc := NewService(store, newCipher(t))
	ctx := context.Background()

	// Geçersiz eylem reddedilir; COLLECTED elle eklenemez.
	if _, err := svc.RecordCustody(ctx, "dev-9", "art-1", "soc@x", "BOGUS"); err == nil {
		t.Error("geçersiz eylem reddedilmeli")
	}
	if _, err := svc.RecordCustody(ctx, "dev-9", "art-1", "soc@x", "COLLECTED"); err == nil {
		t.Error("COLLECTED elle eklenemez")
	}
	// Olmayan artefakt → ErrArtifactNotFound.
	if _, err := svc.RecordCustody(ctx, "dev-9", "yok", "soc@x", "ACCESSED"); err != ErrArtifactNotFound {
		t.Errorf("olmayan artefakt ErrArtifactNotFound dönmeli: %v", err)
	}

	e1, err := svc.RecordCustody(ctx, "dev-9", "art-1", "soc@x", "ACCESSED")
	if err != nil || e1.Seq != 1 || e1.Action != "ACCESSED" {
		t.Fatalf("ACCESSED seq=1 beklenir: %+v (%v)", e1, err)
	}
	e2, err := svc.RecordCustody(ctx, "dev-9", "art-1", "ir@x", "SEALED")
	if err != nil || e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Fatalf("SEALED seq=2 + prev=e1.hash beklenir: %+v", e2)
	}

	// DeviceEvidence: genesis + 2 kalıcı kayıt = 3, doğrulanmış.
	ev, err := svc.DeviceEvidence(ctx, "dev-9")
	if err != nil || len(ev) != 1 {
		t.Fatalf("1 delil: %v", err)
	}
	if len(ev[0].Custody) != 3 {
		t.Fatalf("genesis+2 = 3 gözetim kaydı beklenir, %d", len(ev[0].Custody))
	}
	if !ev[0].Verified {
		t.Error("kalıcı zincir doğrulanmalı")
	}
}
