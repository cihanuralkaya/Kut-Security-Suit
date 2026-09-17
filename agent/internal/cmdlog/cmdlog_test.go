package cmdlog

import (
	"testing"
	"time"
)

func TestRecordExecutedAckRoundtrip(t *testing.T) {
	dir := t.TempDir()
	l := Open(dir)

	if l.Executed("c1") {
		t.Fatal("kaydedilmemiş komut yürütülmüş görünmemeli")
	}
	l.Record("c1")
	if !l.Executed("c1") {
		t.Fatal("kaydedilen komut yürütülmüş olmalı (idempotency)")
	}
	l.QueueAck("c1")
	if got := l.TakeAcks(); len(got) != 1 || got[0] != "c1" {
		t.Fatalf("ack kuyruğu yanlış: %v", got)
	}
	// TakeAcks kuyruğu boşaltmaz.
	if got := l.TakeAcks(); len(got) != 1 {
		t.Fatal("TakeAcks kuyruğu boşaltmamalı")
	}
	l.ConfirmAcks([]string{"c1"})
	if got := l.TakeAcks(); len(got) != 0 {
		t.Fatalf("ConfirmAcks sonrası kuyruk boş olmalı: %v", got)
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	l := Open(dir)
	l.Record("c-persist")
	// Yeni örnek (ajan yeniden başlatması) aynı dizinden yüklemeli.
	l2 := Open(dir)
	if !l2.Executed("c-persist") {
		t.Fatal("yürütülen komut ajan yeniden başlatmasından sonra hatırlanmalı (idempotency)")
	}
}

func TestPruneOldEntries(t *testing.T) {
	dir := t.TempDir()
	l := Open(dir)
	// Saati geriye alarak eski bir kayıt üret, sonra bugüne dönüp prune tetikle.
	old := time.Now().Add(-48 * time.Hour)
	l.now = func() time.Time { return old }
	l.Record("c-old")
	l.now = time.Now
	l.Record("c-new") // Record içinde prune çalışır
	if l.Executed("c-old") {
		t.Fatal("TTL'i geçmiş kayıt budanmalıydı")
	}
	if !l.Executed("c-new") {
		t.Fatal("yeni kayıt korunmalı")
	}
}

func TestEmptyIDIgnored(t *testing.T) {
	l := Open(t.TempDir())
	l.Record("")
	l.QueueAck("")
	if l.Executed("") {
		t.Fatal("boş id asla yürütülmüş sayılmamalı")
	}
	if got := l.TakeAcks(); len(got) != 0 {
		t.Fatalf("boş id ack'lenmemeli: %v", got)
	}
}
