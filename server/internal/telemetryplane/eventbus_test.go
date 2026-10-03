package telemetryplane

import (
	"testing"
	"time"
)

func TestEventBus_PublishSubscribe(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	sub, err := bus.Subscribe("tenant1", "metric.cpu", 10)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}

	evt := BusEvent{
		ID:        "evt-1",
		Topic:     "metric.cpu",
		TenantID:  "tenant1",
		Payload:   []byte("test data"),
		Timestamp: time.Now(),
	}

	if err := bus.Publish(evt); err != nil {
		t.Fatalf("yayınlama hatası: %v", err)
	}

	select {
	case received := <-sub.Channel:
		if received.ID != evt.ID {
			t.Errorf("beklenen olay kimliği %s, alınan %s", evt.ID, received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("olay zaman aşımına uğradı, alınamadı")
	}
}

func TestEventBus_TopicMatching(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	// Wildcard abonelik (prefix matching)
	subWildcard, _ := bus.Subscribe("tenant1", "metric.*", 10)
	// Tam eşleşen abonelik (exact matching)
	subExact, _ := bus.Subscribe("tenant1", "log.error", 10)

	// Wildcard ile eşleşmeli
	bus.Publish(BusEvent{Topic: "metric.memory", TenantID: "tenant1"})

	select {
	case <-subWildcard.Channel:
		// Başarılı, olay alındı
	default:
		t.Fatal("wildcard eşleşmesi çalışmadı, olay bekleniyordu")
	}

	// Exact match test
	bus.Publish(BusEvent{Topic: "log.error", TenantID: "tenant1"})
	select {
	case <-subExact.Channel:
		// Başarılı
	default:
		t.Fatal("tam eşleşme çalışmadı, olay bekleniyordu")
	}

	// Eşleşmemesi gereken durum
	bus.Publish(BusEvent{Topic: "log.info", TenantID: "tenant1"})
	select {
	case <-subExact.Channel:
		t.Fatal("olay eşleşmemeliydi, ancak alındı")
	default:
		// Başarılı (hiçbir şey gelmedi)
	}
}

func TestEventBus_TenantIsolation(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	sub1, _ := bus.Subscribe("tenant1", "system.*", 10)
	sub2, _ := bus.Subscribe("tenant2", "system.*", 10)
	subAll, _ := bus.Subscribe("*", "system.*", 10) // Platform genelini izleyen abone

	bus.Publish(BusEvent{Topic: "system.cpu", TenantID: "tenant1"})

	select {
	case <-sub1.Channel:
	default:
		t.Fatal("tenant1 kendi olayı almalıydı")
	}

	select {
	case <-sub2.Channel:
		t.Fatal("tenant2, tenant1'in olayını almamalıydı (izolasyon başarısız)")
	default:
	}

	select {
	case <-subAll.Channel:
	default:
		t.Fatal("platform wildcard abonesi olayı almalıydı")
	}
}

func TestEventBus_BufferDropAndBackpressure(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	// Kapasitesi tam olarak 1 olan bir kanal tanımlanıyor
	sub, _ := bus.Subscribe("tenant1", "metric", 1)

	// İlk olayı gönder
	bus.Publish(BusEvent{Topic: "metric", TenantID: "tenant1", ID: "evt-1"})

	// İkinci olayı gönder (kanal dolu olduğu için bloklanmamalı ve olay düşürülmeli)
	err := bus.Publish(BusEvent{Topic: "metric", TenantID: "tenant1", ID: "evt-2"})
	if err != nil {
		t.Fatalf("yayınlanırken hata dönmemeliydi: %v", err)
	}

	// Sadece ilk olayı alabilmeliyiz
	evt1 := <-sub.Channel
	if evt1.ID != "evt-1" {
		t.Errorf("beklenen olay kimliği 'evt-1', ancak '%s' alındı", evt1.ID)
	}

	// İkinci olay kanala girememiş olmalı
	select {
	case <-sub.Channel:
		t.Fatal("2. olay düşürülmeliydi, ancak kanalda bulundu")
	default:
		// Başarılı
	}
}

func TestEventBus_UnsubscribeAndLifecycle(t *testing.T) {
	bus := NewEventBus()

	sub, _ := bus.Subscribe("tenant1", "metric", 10)
	bus.Unsubscribe(sub)

	// Unsubscribe sonrasında kanal kapanmış olmalı, yeni veri alınmamalı
	_, ok := <-sub.Channel
	if ok {
		t.Fatal("abonelik iptal edildikten sonra kanalın kapalı olması gerekiyordu")
	}

	// Close operasyonu ve kapalı bus'a yayın yapma testleri
	bus.Close()
	err := bus.Publish(BusEvent{Topic: "metric", TenantID: "tenant1"})
	if err != ErrBusClosed {
		t.Fatalf("beklenen hata ErrBusClosed, ancak %v alındı", err)
	}
}
