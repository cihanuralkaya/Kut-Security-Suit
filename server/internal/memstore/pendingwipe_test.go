package memstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// TestConsumePendingWipe_AtomicSingleWinner, G-08'i kanıtlar: aynı bekleyen WIPE talebine
// N eşzamanlı onaylayan çağırdığında yalnız BİRİ talebi tüketir (çift-enqueue yok).
// -race altında koşunca atomik claim'in doğruluğu doğrulanır.
func TestConsumePendingWipe_AtomicSingleWinner(t *testing.T) {
	s := New()
	ctx := context.Background()
	const dev = "dev-x"
	if err := s.SavePendingWipe(ctx, dev, "requester", "reason"); err != nil {
		t.Fatal(err)
	}
	const N = 32
	var winners int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, consumed, err := s.ConsumePendingWipe(ctx, dev, "approver")
			if err != nil {
				t.Errorf("consume: %v", err)
				return
			}
			if consumed {
				atomic.AddInt64(&winners, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners != 1 {
		t.Fatalf("tam olarak 1 kazanan bekleniyordu, %d oldu (çift-enqueue riski)", winners)
	}
	if _, ok, _ := s.GetPendingWipe(ctx, dev); ok {
		t.Fatal("consume sonrası talep silinmeliydi")
	}
}

// TestConsumePendingWipe_SelfApprovalKeepsPending, kendi talebini onaylamanın (dört-göz)
// talebi TÜKETMEDEN reddedildiğini doğrular.
func TestConsumePendingWipe_SelfApprovalKeepsPending(t *testing.T) {
	s := New()
	ctx := context.Background()
	const dev = "dev-y"
	_ = s.SavePendingWipe(ctx, dev, "adminA", "r")
	rb, consumed, err := s.ConsumePendingWipe(ctx, dev, "adminA")
	if err != nil || consumed || rb != "adminA" {
		t.Fatalf("self-approval (adminA,false) bekleniyordu: rb=%q consumed=%v err=%v", rb, consumed, err)
	}
	if _, ok, _ := s.GetPendingWipe(ctx, dev); !ok {
		t.Fatal("self-approval talebi silmemeliydi")
	}
}

// TestConsumePendingWipe_NonePending, talep yokken ("", false) döndüğünü doğrular.
func TestConsumePendingWipe_NonePending(t *testing.T) {
	s := New()
	rb, consumed, err := s.ConsumePendingWipe(context.Background(), "nope", "x")
	if err != nil || consumed || rb != "" {
		t.Fatalf("talep yokken (\"\",false) bekleniyordu: rb=%q consumed=%v err=%v", rb, consumed, err)
	}
}
