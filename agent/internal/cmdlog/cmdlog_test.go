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

// TestResultQueueRoundtrip, yürütme-sonucu kuyruğunun retry-until-confirmed
// semantiğini doğrular: TakeResults boşaltmaz; yalnız ConfirmResults çıkarır.
func TestResultQueueRoundtrip(t *testing.T) {
	l := Open(t.TempDir())
	l.QueueResult("c1", true, 1, "")
	l.QueueResult("c2", false, 1, "hata")
	l.QueueResult("", true, 0, "") // boş id yok sayılır
	if got := l.TakeResults(); len(got) != 2 {
		t.Fatalf("2 sonuç bekleniyordu: %d", len(got))
	}
	// TakeResults kuyruğu boşaltmaz (heartbeat başarısız olursa yeniden denenir).
	if len(l.TakeResults()) != 2 {
		t.Fatal("TakeResults kuyruğu boşaltmamalı (retry-until-confirmed)")
	}
	l.ConfirmResults([]string{"c1"})
	rem := l.TakeResults()
	if len(rem) != 1 || rem[0].ID != "c2" || rem[0].OK {
		t.Fatalf("yalnız c2 (FAILED) kalmalıydı: %+v", rem)
	}
	l.ConfirmResults([]string{"c2"})
	if l.TakeResults() != nil {
		t.Fatal("tüm sonuçlar onaylandıktan sonra kuyruk boş olmalı")
	}
}
