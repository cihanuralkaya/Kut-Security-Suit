//go:build enterprise

// durable.go (enterprise), telemetri bildirimleri için dayanıklı (at-least-once) bir kayıt
// sağlar. Dış broker (Redpanda) gelene kadar enterprise bus bu DOSYA-TABANLI kaydı kullanır;
// Redpanda backend'i AYNI DurableLog arayüzünü uygular. Bu dosya HİÇBİR dış bağımlılık
// import etmez (yalnız stdlib) — böylece nested-module (B) terfisi ilk gerçek ağır istemciye
// ertelenebilir, Lite grafiği temiz kalır (bkz. docs/BUILD-TIERS.md).
package bus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"kut.corp/suite/server/internal/eventbus"
)

// DurableLog, bildirimleri kalıcı olarak yazan ve baştan yeniden oynatabilen at-least-once
// bir kayıttır. CONTRACT-FREEZE: bu imza dondurulmuştur — dosya backend'i de Redpanda
// backend'i de bunu uygular; downstream tüketiciler yalnız bu arayüze bağlanır.
type DurableLog interface {
	// Append, bildirimi kalıcı ortama yazar. Dönmeden önce kaydın diske ulaştığını
	// (fsync) garanti eder; nil dönerse kayıt dayanıklıdır.
	Append(n eventbus.Notice) error
	// Replay, kaydı EN ESKİDEN EN YENİYE fn ile çağırır. fn hata dönerse oynatma durur
	// ve o hata döner (tüketici kendi ilerleme/onay mantığını uygular).
	Replay(fn func(eventbus.Notice) error) error
	// Close, tamponu boşaltır ve alttaki tanıtıcıyı kapatır. Idempotent olması beklenir.
	Close() error
}

// defaultMaxLogBytes, bir nesil dosyanın rotasyon eşiğidir: aktif dosya bunu aşınca
// döndürülür (sınırsız büyüme footgun'ına karşı). defaultMaxGens ise tutulacak
// döndürülmüş nesil sayısıdır — toplam disk (maxGens+1)*maxBytes ile sınırlıdır ve en
// eski nesil düşer (retention). Redpanda backend'inde retention broker tarafından
// yönetilir; dosya backend'i basit ve sınırlı kalır.
const (
	defaultMaxLogBytes int64 = 64 << 20 // nesil başına 64 MiB
	defaultMaxGens     int   = 8        // .1..8 → ~576 MiB tavan
)

// fileLog, DurableLog'un append-only JSONL dosya implementasyonudur. Çok-nesilli rotasyon
// (aktif dosya + `.1`..`.N`) ve per-append fsync ile "retention penceresi içinde at-least-once"
// dayanıklılık sağlar: pencere aşılırsa YALNIZ en eski nesil düşer, aradaki kayıtlar korunur.
type fileLog struct {
	mu        sync.Mutex
	path      string
	maxBytes  int64
	maxGens   int
	f         *os.File
	w         *bufio.Writer
	size      int64
	appendErr uint64 // atomik: kalıcı yazma hatası sayacı (gözlem)
	closed    bool
}

// NewFileLog, verilen yolda append-only dayanıklı kaydı açar/oluşturur (varsayılan
// rotasyon eşiği ve nesil sayısı). Üst dizin mevcut olmalıdır.
func NewFileLog(path string) (*fileLog, error) {
	return newFileLog(path, defaultMaxLogBytes, defaultMaxGens)
}

// newFileLog, ayarlanabilir rotasyon eşiği/nesil sayısıyla kaydı açar (test için ayrık).
func newFileLog(path string, maxBytes int64, maxGens int) (*fileLog, error) {
	if path == "" {
		return nil, fmt.Errorf("dayanıklı bus: boş yol")
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxLogBytes
	}
	if maxGens < 1 {
		maxGens = defaultMaxGens
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("dayanıklı bus: açılamadı %q: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("dayanıklı bus: stat %q: %w", path, err)
	}
	return &fileLog{path: path, maxBytes: maxBytes, maxGens: maxGens, f: f, w: bufio.NewWriter(f), size: st.Size()}, nil
}

// genPath, k. döndürülmüş nesil dosyasının yolunu döner (k≥1 → path.k).
func (l *fileLog) genPath(k int) string { return l.path + "." + strconv.Itoa(k) }

// Append, bildirimi JSONL olarak ekler; gerekiyorsa önce rotasyon yapar, sonra fsync eder.
func (l *fileLog) Append(n eventbus.Notice) error {
	rec, err := json.Marshal(n)
	if err != nil {
		atomic.AddUint64(&l.appendErr, 1)
		return fmt.Errorf("dayanıklı bus: kodlama: %w", err)
	}
	rec = append(rec, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		atomic.AddUint64(&l.appendErr, 1)
		return fmt.Errorf("dayanıklı bus: kapalı kayda yazma")
	}
	// Çok-nesilli rotasyon: aktif dosya eşiği aşacaksa nesilleri kaydır ve `.1`'e döndür.
	// Boş dosyayı döndürmeyiz (tek başına eşikten büyük bir kayıt yine de yazılır).
	if l.size > 0 && l.size+int64(len(rec)) > l.maxBytes {
		if err := l.rotateLocked(); err != nil {
			atomic.AddUint64(&l.appendErr, 1)
			return err
		}
	}
	if _, err := l.w.Write(rec); err != nil {
		atomic.AddUint64(&l.appendErr, 1)
		return fmt.Errorf("dayanıklı bus: yazma: %w", err)
	}
	if err := l.w.Flush(); err != nil {
		atomic.AddUint64(&l.appendErr, 1)
		return fmt.Errorf("dayanıklı bus: flush: %w", err)
	}
	if err := l.f.Sync(); err != nil { // at-least-once: kayıt diske ulaşana kadar dönme
		atomic.AddUint64(&l.appendErr, 1)
		return fmt.Errorf("dayanıklı bus: fsync: %w", err)
	}
	l.size += int64(len(rec))
	return nil
}

// rotateLocked, aktif dosyayı kapatır, nesilleri kaydırır (en eski `.maxGens` düşer:
// `.k`→`.k+1`), aktif dosyayı `.1` yapar ve taze bir aktif dosya açar. Çağıran mu'yu
// tutmalıdır. Kaydırma en eskiden başlar ki hiçbir nesil üzerine yazılmasın.
func (l *fileLog) rotateLocked() error {
	if err := l.w.Flush(); err != nil {
		return fmt.Errorf("dayanıklı bus: rotasyon flush: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("dayanıklı bus: rotasyon kapatma: %w", err)
	}
	// En eski nesli düşür, sonra .k→.k+1 (yüksekten alçağa kaydır).
	if err := os.Remove(l.genPath(l.maxGens)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("dayanıklı bus: en eski nesil silme: %w", err)
	}
	for k := l.maxGens - 1; k >= 1; k-- {
		if err := os.Rename(l.genPath(k), l.genPath(k+1)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("dayanıklı bus: nesil kaydırma %d→%d: %w", k, k+1, err)
		}
	}
	if err := os.Rename(l.path, l.genPath(1)); err != nil {
		return fmt.Errorf("dayanıklı bus: rotasyon rename: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("dayanıklı bus: rotasyon yeniden açma: %w", err)
	}
	l.f = f
	l.w = bufio.NewWriter(f)
	l.size = 0
	return nil
}

// Replay, en eski nesilden (`.maxGens`) aktif dosyaya doğru satır satır okur
// (en eski→en yeni). Var olmayan nesiller sessizce atlanır.
func (l *fileLog) Replay(fn func(eventbus.Notice) error) error {
	l.mu.Lock()
	paths := make([]string, 0, l.maxGens+1)
	for k := l.maxGens; k >= 1; k-- {
		paths = append(paths, l.genPath(k))
	}
	paths = append(paths, l.path)
	l.mu.Unlock()
	for _, p := range paths {
		if err := replayFile(p, fn); err != nil {
			return err
		}
	}
	return nil
}

// replayFile, tek bir JSONL dosyasını oynatır. Dosya yoksa sessizce atlanır.
func replayFile(path string, fn func(eventbus.Notice) error) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("dayanıklı bus: oynatma açma %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // uzun kayıtlara tolerans
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var n eventbus.Notice
		if err := json.Unmarshal(line, &n); err != nil {
			// Bozuk/yarım satır (ör. çökme anında): oynatmayı kesme, atla.
			continue
		}
		if err := fn(n); err != nil {
			return err
		}
	}
	return sc.Err()
}

// AppendErrors, şimdiye kadarki kalıcı yazma hatası sayısını döner (gözlem/test).
func (l *fileLog) AppendErrors() uint64 { return atomic.LoadUint64(&l.appendErr) }

// Close, tamponu boşaltır ve dosyayı kapatır. Idempotenttir.
func (l *fileLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if err := l.w.Flush(); err != nil {
		_ = l.f.Close()
		return fmt.Errorf("dayanıklı bus: kapatma flush: %w", err)
	}
	return l.f.Close()
}
