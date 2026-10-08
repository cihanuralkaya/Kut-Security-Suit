package telemetryplane

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// BusEvent, sistem içinde taşınan temel olay yapısıdır.
type BusEvent struct {
	ID        string
	Topic     string
	TenantID  string
	Payload   []byte
	Timestamp time.Time
}

// Subscriber, bir abonenin durumunu ve olayları alacağı kanalı tutar.
type Subscriber struct {
	ID           string
	TenantID     string
	TopicPattern string
	Channel      chan BusEvent
}

// EventBus, olayların yayınlanması ve abonelere dağıtılmasını yönetir.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string]*Subscriber
	closed      bool
}

// NewEventBus, yeni bir EventBus örneği oluşturur.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string]*Subscriber),
	}
}

// ErrBusClosed, kapalı bir EventBus üzerinden işlem yapılmaya çalışıldığında döner.
var ErrBusClosed = errors.New("event bus is closed")

// Publish, bir olayı eşleşen tüm abonelere iletir.
// Kanalı dolu olan aboneler için olay düşürülür (non-blocking).
func (b *EventBus) Publish(evt BusEvent) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return ErrBusClosed
	}

	for _, sub := range b.subscribers {
		// Tenant izolasyonu kontrolü. "*" veya boş değer platform genelini ifade eder.
		if sub.TenantID != "" && sub.TenantID != "*" && sub.TenantID != evt.TenantID {
			continue
		}

		// Topic eşleşme kontrolü
		if !matchTopic(sub.TopicPattern, evt.Topic) {
			continue
		}

		// Olayı kanala gönder, kanal doluysa olayı düşür (drop/backpressure policy)
		select {
		case sub.Channel <- evt:
		default:
			// Kanal dolu, olayı backpressure stratejisi gereği düşürüyoruz.
		}
	}

	return nil
}

// Subscribe, belirli bir tenant ve konu desenine abone olmak için kullanılır.
func (b *EventBus) Subscribe(tenantID string, topicPattern string, bufSize int) (*Subscriber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrBusClosed
	}

	subID := generateID()
	sub := &Subscriber{
		ID:           subID,
		TenantID:     tenantID,
		TopicPattern: topicPattern,
		Channel:      make(chan BusEvent, bufSize),
	}

	b.subscribers[subID] = sub
	return sub, nil
}

// Unsubscribe, aboneyi sistemden çıkarır ve kanalını kapatır.
func (b *EventBus) Unsubscribe(sub *Subscriber) {
	if sub == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.subscribers[sub.ID]; exists {
		delete(b.subscribers, sub.ID)
		close(sub.Channel) // Kanalı kapatarak dinleyenleri uyar
	}
}

// Close, EventBus'ı kapatır ve tüm abonelikleri temizler.
func (b *EventBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}
	b.closed = true

	for id, sub := range b.subscribers {
		close(sub.Channel)
		delete(b.subscribers, id)
	}
}

// matchTopic, topic pattern eşleşmesini kontrol eder (exact match veya prefix match).
func matchTopic(pattern, topic string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(topic, prefix)
	}
	return pattern == topic
}
