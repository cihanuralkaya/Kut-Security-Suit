//go:build enterprise

// jetstream.go (enterprise), DurableLog'u NATS JetStream ile uygular — dosya backend'inin
// yanında ikinci, ölçeklenebilir kademe (bkz. Desktop araştırma raporu / docs/BUILD-TIERS.md).
// JetStream Go-native'dir ve sunucusu SÜREÇ İÇİNE GÖMÜLEBİLİR: KUT_NATS_URL boşsa gömülü bir
// sunucu başlatılır (tek-binary DNA'sına uyar ve testler dış servis olmadan koşar); doluysa
// mevcut harici NATS/JetStream kümesine bağlanılır. Bu dosya ve importları YALNIZ
// `//go:build enterprise` arkasındadır → Lite c2 binary'si NATS'ı derlemez (zero-dep guard korunur).
package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	natsd "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"kut.corp/suite/server/internal/eventbus"
)

const (
	jsStreamName = "KUT_BUS"
	jsSubject    = "kut.bus"
)

// jetStreamLog, DurableLog'un JetStream implementasyonudur. Gömülü sunucu başlattıysa onu da
// kapatmaktan sorumludur (ns != nil).
type jetStreamLog struct {
	ns     *natsd.Server // yalnız gömülü modda dolu
	nc     *nats.Conn
	js     jetstream.JetStream
	stream jetstream.Stream
}

// NewJetStreamLog, JetStream destekli dayanıklı kaydı açar. url boşsa storeDir altında gömülü
// bir sunucu başlatılır ve süreç-içi (portsuz) bağlanılır; doluysa harici url'ye bağlanılır.
func NewJetStreamLog(url, storeDir string) (*jetStreamLog, error) {
	var ns *natsd.Server
	var nc *nats.Conn
	var err error

	if url == "" {
		if storeDir == "" {
			storeDir = "kut-jetstream"
		}
		opts := &natsd.Options{
			ServerName:         "kut-embedded",
			Host:               "127.0.0.1",
			Port:               -1, // rastgele boş port (süreç-içi bağlantı port kullanmaz)
			JetStream:          true,
			StoreDir:           storeDir,
			NoLog:              true,
			NoSigs:             true,
			JetStreamMaxMemory: -1,
			JetStreamMaxStore:  -1,
		}
		ns, err = natsd.NewServer(opts)
		if err != nil {
			return nil, fmt.Errorf("dayanıklı bus (jetstream): gömülü sunucu: %w", err)
		}
		go ns.Start()
		if !ns.ReadyForConnections(5 * time.Second) {
			ns.Shutdown()
			return nil, fmt.Errorf("dayanıklı bus (jetstream): gömülü sunucu hazır olmadı")
		}
		nc, err = nats.Connect("", nats.InProcessServer(ns)) // TCP değil, süreç-içi
	} else {
		nc, err = nats.Connect(url, nats.Name("kut-bus"), nats.MaxReconnects(-1))
	}
	if err != nil {
		if ns != nil {
			ns.Shutdown()
		}
		return nil, fmt.Errorf("dayanıklı bus (jetstream): bağlantı: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		if ns != nil {
			ns.Shutdown()
		}
		return nil, fmt.Errorf("dayanıklı bus (jetstream): js bağlamı: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        jsStreamName,
		Subjects:    []string{jsSubject},
		Storage:     jetstream.FileStorage, // dayanıklı (disk)
		Retention:   jetstream.LimitsPolicy,
		Discard:     jetstream.DiscardOld, // sınır aşılırsa en eskiyi düşür (retention)
		AllowDirect: true,
	})
	if err != nil {
		nc.Close()
		if ns != nil {
			ns.Shutdown()
		}
		return nil, fmt.Errorf("dayanıklı bus (jetstream): stream: %w", err)
	}
	return &jetStreamLog{ns: ns, nc: nc, js: js, stream: stream}, nil
}

// Append, bildirimi JetStream'e yayınlar ve sunucu ACK'ini BEKLER (at-least-once dayanıklılık).
func (l *jetStreamLog) Append(n eventbus.Notice) error {
	data, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("dayanıklı bus (jetstream): kodlama: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.js.Publish(ctx, jsSubject, data); err != nil { // ACK beklenir
		return fmt.Errorf("dayanıklı bus (jetstream): yayın: %w", err)
	}
	return nil
}

// Replay, stream'deki tüm bildirimleri en eskiden en yeniye fn ile çağırır. Geçici (ephemeral)
// bir pull tüketici kullanır; oynatma bitince tüketiciyi siler. Boş stream'de hemen döner.
func (l *jetStreamLog) Replay(fn func(eventbus.Notice) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	si, err := l.stream.Info(ctx)
	if err != nil {
		return fmt.Errorf("dayanıklı bus (jetstream): stream bilgisi: %w", err)
	}
	if si.State.Msgs == 0 {
		return nil
	}
	target := si.State.LastSeq

	cons, err := l.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		AckPolicy:         jetstream.AckExplicitPolicy,
		InactiveThreshold: time.Minute,
	})
	if err != nil {
		return fmt.Errorf("dayanıklı bus (jetstream): tüketici: %w", err)
	}
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		_ = l.stream.DeleteConsumer(dctx, cons.CachedInfo().Name)
	}()

	for {
		mb, err := cons.Fetch(200, jetstream.FetchMaxWait(3*time.Second))
		if err != nil {
			return fmt.Errorf("dayanıklı bus (jetstream): fetch: %w", err)
		}
		got := 0
		for msg := range mb.Messages() {
			got++
			_ = msg.Ack()
			var n eventbus.Notice
			if err := json.Unmarshal(msg.Data(), &n); err != nil {
				continue // bozuk kayıt: atla, oynatmayı kesme
			}
			if err := fn(n); err != nil {
				return err
			}
			if meta, merr := msg.Metadata(); merr == nil && meta.Sequence.Stream >= target {
				return mb.Error() // hedefe (son sıra) ulaşıldı
			}
		}
		if err := mb.Error(); err != nil {
			return fmt.Errorf("dayanıklı bus (jetstream): batch: %w", err)
		}
		if got == 0 {
			return nil // tükendi
		}
	}
}

// Close, bağlantıyı boşaltır; gömülü sunucu başlatıldıysa onu da kapatır. Idempotenttir.
func (l *jetStreamLog) Close() error {
	if l.nc != nil && !l.nc.IsClosed() {
		_ = l.nc.Drain()
	}
	if l.ns != nil {
		l.ns.Shutdown()
		l.ns.WaitForShutdown()
	}
	return nil
}
