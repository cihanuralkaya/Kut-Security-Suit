// Package cmdlog, ajanın YÜRÜTTÜĞÜ komut kimliklerini KALICI olarak tutar
// (idempotency) ve sunucuya bildirilecek ONAY (ack) kuyruğunu yönetir. En-az-bir-kez
// teslim modelinde bir komut ajan çökse/heartbeat kaçsa bile yeniden teslim edilir;
// cmdlog sayesinde ajan aynı komutu İKİNCİ KEZ YÜRÜTMEZ (WIPE/LOCK gibi yıkıcı
// işlemlerde kritik) ve yürüttüğü komutları heartbeat'te acked_command_ids ile
// onaylar (sunucu yeniden-teslimi durdurur).
//
// Kalıcılık, ajan yeniden başlasa bile idempotency'nin sürmesi içindir. Girdiler
// bir TTL sonrası budanır (yeniden-teslim penceresi kısa; sınırsız büyüme yok).
// Bağımlılıksız (yalnız stdlib).
package cmdlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ttl, bir yürütülen-komut kaydının tutulma süresidir. Sunucu vazgeçme penceresinden
// (lease × azami-deneme) kat kat uzun; böylece redelivery boyunca idempotency korunur.
const ttl = 24 * time.Hour

// Log, yürütülen komut kimliklerini (kalıcı) ve ack kuyruğunu (geçici) tutar.
type Log struct {
	mu       sync.Mutex
	path     string
	executed map[string]int64    // komut id -> yürütülme anı (unix); kalıcı
	acks     map[string]struct{} // bildirilecek onaylar; geçici
	now      func() time.Time
}

// Open, dataDir/executed-commands.json dosyasından yürütülen-komut kaydını yükler
// (yoksa boş başlar). Bozuk/okunamayan dosya sessizce yok sayılır (idempotency
// best-effort; en kötü durumda bir komut bir kez daha yürütülür).
func Open(dataDir string) *Log {
	l := &Log{
		path:     filepath.Join(dataDir, "executed-commands.json"),
		executed: map[string]int64{},
		acks:     map[string]struct{}{},
		now:      time.Now,
	}
	if b, err := os.ReadFile(l.path); err == nil {
		var m map[string]int64
		if json.Unmarshal(b, &m) == nil {
			l.executed = m
		}
	}
	l.pruneLocked()
	return l
}

// Executed, komut daha önce yürütülmüşse true döner (idempotency kontrolü).
func (l *Log) Executed(id string) bool {
	if id == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.executed[id]
	return ok
}

// Record, komutu YÜRÜTÜLDÜ olarak kaydeder (idempotency) ve diske yazar. Boş id
// yok sayılır.
func (l *Log) Record(id string) {
	if id == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.executed[id] = l.now().Unix()
	l.pruneLocked()
	l.saveLocked()
}

// QueueAck, komutu sunucuya bildirilecek onay kuyruğuna ekler.
func (l *Log) QueueAck(id string) {
	if id == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.acks[id] = struct{}{}
}

// TakeAcks, o an bildirilecek onay kimliklerinin anlık kopyasını döner (kuyruğu
// BOŞALTMAZ — heartbeat başarılı olursa ConfirmAcks ile temizlenir; başarısızsa
// yeniden denenir).
func (l *Log) TakeAcks() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.acks) == 0 {
		return nil
	}
	out := make([]string, 0, len(l.acks))
	for id := range l.acks {
		out = append(out, id)
	}
	return out
}

// ConfirmAcks, sunucuya BAŞARIYLA bildirilen onayları kuyruktan çıkarır.
func (l *Log) ConfirmAcks(ids []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, id := range ids {
		delete(l.acks, id)
	}
}

// pruneLocked, TTL'i geçmiş kayıtları siler (kilit çağıranda).
func (l *Log) pruneLocked() {
	cutoff := l.now().Add(-ttl).Unix()
	for id, t := range l.executed {
		if t < cutoff {
			delete(l.executed, id)
		}
	}
}

// saveLocked, yürütülen-komut kaydını atomik (temp + rename) diske yazar (kilit
// çağıranda). Hata best-effort yok sayılır (kalıcılık kaybı yalnız idempotency'yi
// zayıflatır, doğruluğu bozmaz).
func (l *Log) saveLocked() {
	b, err := json.Marshal(l.executed)
	if err != nil {
		return
	}
	tmp := l.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, l.path)
	}
}
