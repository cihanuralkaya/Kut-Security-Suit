// Package threshold, TEKRAR-EŞİKLİ alarm kapısı sağlar (IDS `threshold` /
// `detection_filter` keyword ailesinin uç-nokta uyarlaması). Mevcut correlate
// paketi TERS yönü çözer — yinelenen alarmları BASTIRIR (ilki geçer). Burası
// eksik yönü çözer: bir tespit, bir zaman penceresinde EN AZ N kez görülmeden
// alarm ÜRETİLMEZ. Böylece tek bir başarısız oturum/tarama denemesi gürültü
// yapmaz ama brute-force / yatay-tarama (çok tekrar) yüksek-güvenle yakalanır.
//
// Kapı OPT-IN'dir: yalnız eşik tanımlı kurallar (detect.Rule.Threshold) için
// çağrılır; eşiği olmayan kuralların davranışı DEĞİŞMEZ (varsayılan = her tespit
// alarm adayı). Durum bellek-içidir (correlate ile aynı desen). Bağımlılıksız.
package threshold

import (
	"sync"
	"time"
)

// counter, tek bir (kural|kapsam) anahtarının TUMBLING (devrilen) penceresidir.
type counter struct {
	hits int
	from time.Time // pencere başlangıcı
}

// Gate, (kural|kapsam) başına eşik sayacı tutar (eşzamanlı-güvenli).
type Gate struct {
	mu  sync.Mutex
	ctr map[string]*counter
	now func() time.Time
	max int // izlenen anahtar üst sınırı (bellek sınırlama)
}

// New, boş bir kapı kurar. now nil → time.Now.
func New(now func() time.Time) *Gate {
	if now == nil {
		now = time.Now
	}
	return &Gate{ctr: map[string]*counter{}, now: now, max: 100_000}
}

// Allow, bir tespit için eşik kapısını uygular ve alarmın GEÇMESİ gerekip
// gerekmediğini döner. count<=1 ise eşik anlamsızdır → daima true (uyumluluk).
// Aksi halde (ruleID|scope) anahtarı için pencerede vuruş sayılır; sayaç count'a
// ULAŞTIĞINDA true döner ve pencere SIFIRLANIR ("her N olayda 1 alarm"). Pencere
// süresi dolduysa sayaç baştan başlar. false → eşik henüz aşılmadı, alarm bastırılmalı.
func (g *Gate) Allow(ruleID, scope string, count int, window time.Duration) bool {
	if count <= 1 {
		return true
	}
	if window <= 0 {
		window = time.Minute
	}
	k := ruleID + "|" + scope
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked(now, window)
	c := g.ctr[k]
	if c == nil || now.Sub(c.from) > window {
		c = &counter{from: now}
		g.ctr[k] = c
	}
	c.hits++
	if c.hits >= count {
		delete(g.ctr, k) // sıfırla: sonraki alarm için yeniden N vuruş gerekir
		return true
	}
	return false
}

// pruneLocked, anahtar sayısı sınırı aşınca süresi dolmuş sayaçları budar
// (yaklaşık; yalnız bellek üst sınırı için). Kilit çağıran tarafından tutulur.
func (g *Gate) pruneLocked(now time.Time, window time.Duration) {
	if len(g.ctr) <= g.max {
		return
	}
	for k, c := range g.ctr {
		if now.Sub(c.from) > window {
			delete(g.ctr, k)
		}
	}
}

// TrackedCount, o an izlenen (kural|kapsam) anahtar sayısını döner (gözlem/test).
func (g *Gate) TrackedCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.ctr)
}
