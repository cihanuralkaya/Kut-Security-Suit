//go:build enterprise

// kafka.go (enterprise), DurableLog'u Kafka-API (franz-go) ile uygular — dayanıklı bus'ın
// üçüncü kademesi. Amaç: zaten Kafka/Redpanda tabanlı bir güvenlik-veri-hattı işleten büyük
// enterprise'ların KUT'u "mevcut hatlarına takması". franz-go saf-Go'dur (cgo yok). JetStream'in
// aksine broker GÖMÜLEMEZ; harici bir küme (KUT_KAFKA_URL) gerekir ve CI entegrasyon testi bir
// Redpanda servis konteynerine karşı koşar. Import YALNIZ `//go:build enterprise` arkasındadır →
// Lite c2 binary'si franz-go'yu derlemez (zero-dep guard `franz-go`'yu da reddeder).
package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"kut.corp/suite/server/internal/eventbus"
)

const kafkaDefaultTopic = "kut-bus"

// kafkaLog, DurableLog'un franz-go implementasyonudur. Global sıralamayı korumak için tek
// partition'lı bir topic kullanır (DurableLog en-eski→en-yeni sözleşmesi).
type kafkaLog struct {
	seeds []string
	topic string
	cl    *kgo.Client // üretici (idempotent, acks=all — franz-go varsayılanı)
}

// NewKafkaLog, verilen seed broker'lara (virgülle ayrık) bağlanır ve tek partition'lı topic'i
// (yoksa) oluşturur. url boşsa hata döner (broker zorunlu).
func NewKafkaLog(url, topic string) (*kafkaLog, error) {
	if strings.TrimSpace(url) == "" {
		return nil, fmt.Errorf("dayanıklı bus (kafka): KUT_KAFKA_URL gerekli")
	}
	if topic == "" {
		topic = kafkaDefaultTopic
	}
	seeds := splitSeeds(url)
	cl, err := kgo.NewClient(kgo.SeedBrokers(seeds...))
	if err != nil {
		return nil, fmt.Errorf("dayanıklı bus (kafka): istemci: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := cl.Ping(ctx); err != nil {
		cl.Close()
		return nil, fmt.Errorf("dayanıklı bus (kafka): broker'a ulaşılamadı: %w", err)
	}
	// Topic'i tek partition ile oluştur (global sıralama); RF=-1 → broker varsayılanı.
	// "zaten var" hatası tolere edilir.
	adm := kadm.NewClient(cl)
	if _, err := adm.CreateTopic(ctx, 1, -1, nil, topic); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "exists") {
		cl.Close()
		return nil, fmt.Errorf("dayanıklı bus (kafka): topic oluşturma: %w", err)
	}
	return &kafkaLog{seeds: seeds, topic: topic, cl: cl}, nil
}

func splitSeeds(url string) []string {
	parts := strings.Split(url, ",")
	out := parts[:0]
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Append, bildirimi topic'e senkron üretir ve broker ACK'ini bekler (at-least-once).
func (l *kafkaLog) Append(n eventbus.Notice) error {
	data, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("dayanıklı bus (kafka): kodlama: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := l.cl.ProduceSync(ctx, &kgo.Record{Topic: l.topic, Value: data})
	if err := res.FirstErr(); err != nil {
		return fmt.Errorf("dayanıklı bus (kafka): üretim: %w", err)
	}
	return nil
}

// Replay, topic'i baştan sona (replay anındaki uç ofsete kadar) en eskiden en yeniye okur.
// Tüketici grubu KULLANMAZ — her çağrı sıfırdan okur; oynatma bitince tüketici kapatılır.
func (l *kafkaLog) Replay(fn func(eventbus.Notice) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	adm := kadm.NewClient(l.cl)
	ends, err := adm.ListEndOffsets(ctx, l.topic)
	if err != nil {
		return fmt.Errorf("dayanıklı bus (kafka): uç ofset: %w", err)
	}
	end, ok := ends.Lookup(l.topic, 0)
	if !ok || end.Offset == 0 {
		return nil // topic boş
	}
	last := end.Offset - 1 // yazılan son kaydın ofseti

	cons, err := kgo.NewClient(
		kgo.SeedBrokers(l.seeds...),
		kgo.ConsumeTopics(l.topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		return fmt.Errorf("dayanıklı bus (kafka): tüketici: %w", err)
	}
	defer cons.Close()

	for {
		fs := cons.PollFetches(ctx)
		if errs := fs.Errors(); len(errs) > 0 {
			return fmt.Errorf("dayanıklı bus (kafka): fetch: %w", errs[0].Err)
		}
		it := fs.RecordIter()
		for !it.Done() {
			r := it.Next()
			var n eventbus.Notice
			if err := json.Unmarshal(r.Value, &n); err == nil {
				if e := fn(n); e != nil {
					return e
				}
			}
			if r.Offset >= last {
				return nil // hedefe (son ofset) ulaşıldı
			}
		}
	}
}

// Close, üretici istemciyi kapatır. Idempotenttir.
func (l *kafkaLog) Close() error {
	if l.cl != nil {
		l.cl.Close()
		l.cl = nil
	}
	return nil
}
