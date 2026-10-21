package entitygraph

import (
	"strconv"
	"testing"
	"time"
)

// checkInvariants, tüm yapıların (out/in/lru/deg/tenNodes/size) tutarlı olduğunu doğrular.
func checkInvariants(t *testing.T, g *Graph) {
	t.Helper()
	g.mu.RLock()
	defer g.mu.RUnlock()
	outN, inN, lruN := 0, 0, 0
	for _, m := range g.out {
		if len(m) == 0 {
			t.Fatal("boş out haritası kalmamalı")
		}
		outN += len(m)
	}
	for _, m := range g.in {
		if len(m) == 0 {
			t.Fatal("boş in haritası kalmamalı")
		}
		inN += len(m)
	}
	for _, l := range g.lru {
		if l.Len() == 0 {
			t.Fatal("boş LRU listesi kalmamalı")
		}
		lruN += l.Len()
	}
	if outN != g.size || inN != g.size || lruN != g.size {
		t.Fatalf("kenar sayıları tutarsız: size=%d out=%d in=%d lru=%d", g.size, outN, inN, lruN)
	}
	degSum, tenSum := 0, 0
	for _, d := range g.deg {
		degSum += d
	}
	for _, n := range g.tenNodes {
		tenSum += n
	}
	if degSum != 2*g.size || tenSum != len(g.deg) {
		t.Fatalf("düğüm sayaçları tutarsız: degSum=%d (2*size=%d) tenSum=%d deg=%d", degSum, 2*g.size, tenSum, len(g.deg))
	}
}

func node(kind Kind, id, tenant string) Node { return Node{Kind: kind, ID: id, Tenant: tenant} }

// Kiracı kenar tavanı: aşılınca o kiracının EN ESKİ-gözlenen kenarı atılır; başka kiracı etkilenmez.
func TestEdgeCapLRUPerTenant(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerTenant: 5})
	base := time.Unix(1_700_000_000, 0)
	// B kiracısı 3 kenar.
	for i := 0; i < 3; i++ {
		g.Observe(node(Device, "db", "b"), node(Domain, "b"+strconv.Itoa(i), "b"), Resolved, base)
	}
	// A kiracısı 12 benzersiz kenar (tavan 5).
	for i := 0; i < 12; i++ {
		g.Observe(node(Device, "da", "a"), node(Domain, "a"+strconv.Itoa(i), "a"), Resolved, base)
	}
	st := g.Stats()
	if st.Edges != 5+3 {
		t.Fatalf("A en fazla 5 kenar tutmalı (+B'nin 3'ü): %+v", st)
	}
	if st.Evicted != 7 {
		t.Fatalf("7 LRU tahliyesi beklenir: %+v", st)
	}
	// En yeni 5 A kenarı kalmalı, en eskiler gitmiş olmalı.
	have := map[string]bool{}
	for _, n := range g.Targets(node(Device, "da", "a"), Resolved) {
		have[n.ID] = true
	}
	for i := 0; i < 7; i++ {
		if have["a"+strconv.Itoa(i)] {
			t.Fatalf("eski A kenarı a%d tahliye edilmeliydi", i)
		}
	}
	for i := 7; i < 12; i++ {
		if !have["a"+strconv.Itoa(i)] {
			t.Fatalf("yeni A kenarı a%d korunmalıydı", i)
		}
	}
	// NEGATİF: A'nın seli B'nin kenarlarını tahliye ETMEDİ.
	if len(g.Targets(node(Device, "db", "b"), Resolved)) != 3 {
		t.Fatal("B kiracısı A'nın seliyle etkilenmemeli")
	}
	checkInvariants(t, g)
}

// Yeniden gözlenen kenar LRU'da öne geçer (sık kullanılan kenar tahliye edilmez).
func TestLRUKeepsRecentlyObservedEdge(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerTenant: 3})
	ts := time.Unix(1_700_000_000, 0)
	d := node(Device, "d", "a")
	for i := 0; i < 3; i++ {
		g.Observe(d, node(Domain, "x"+strconv.Itoa(i), "a"), Resolved, ts)
	}
	g.Observe(d, node(Domain, "x0", "a"), Resolved, ts) // x0 yeniden gözlendi → en yeni
	g.Observe(d, node(Domain, "x3", "a"), Resolved, ts) // tavan aşımı → en eski (x1) gitmeli
	have := map[string]bool{}
	for _, n := range g.Targets(d, Resolved) {
		have[n.ID] = true
	}
	if !have["x0"] || have["x1"] || !have["x2"] || !have["x3"] {
		t.Fatalf("LRU sırası bozuk: %+v", have)
	}
	checkInvariants(t, g)
}

// Düğüm tavanı: yıldız grafta yaprak düğümleri tavanı aşamaz.
func TestNodeCapPerTenant(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerTenant: 1000, MaxNodesPerTenant: 10})
	ts := time.Unix(1_700_000_000, 0)
	for i := 0; i < 200; i++ {
		g.Observe(node(Device, "hub", "a"), node(IP, "10.0.0."+strconv.Itoa(i), "a"), Connected, ts)
	}
	st := g.Stats()
	if st.Nodes > 10 {
		t.Fatalf("düğüm tavanı 10 aşılmamalı: %+v", st)
	}
	if st.Evicted == 0 {
		t.Fatalf("tahliye olmalıydı: %+v", st)
	}
	checkInvariants(t, g)
}

// Z3-03: 1M benzersiz alan adı gözlemi, tavan altında SINIRLI bellekle sonuçlanır.
func TestMillionDomainFloodStaysBounded(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerTenant: 2000, MaxNodesPerTenant: 2100})
	ts := time.Unix(1_700_000_000, 0)
	dev := node(Device, "dev", "a")
	n := 1_000_000
	if testing.Short() {
		n = 100_000
	}
	for i := 0; i < n; i++ {
		g.Observe(dev, node(Domain, "d"+strconv.Itoa(i)+".evil.example", "a"), Resolved, ts)
	}
	st := g.Stats()
	if st.Edges > 2000 || st.Nodes > 2100 {
		t.Fatalf("graf tavanı aştı: %+v", st)
	}
	if st.Evicted < int64(n-2000) {
		t.Fatalf("taşan her gözlem bir tahliye üretmeli: %+v", st)
	}
	checkInvariants(t, g)
}

// Aşırı uzun kimlik ve çapraz-kiracı kenar REDDEDİLİR (sayılır, graf değişmez).
func TestOversizeIDAndCrossTenantEdgeDropped(t *testing.T) {
	g := New()
	ts := time.Unix(1_700_000_000, 0)
	long := make([]byte, DefaultLimits().MaxIDLen+1)
	for i := range long {
		long[i] = 'a'
	}
	g.Observe(node(Device, "d", "a"), node(Domain, string(long), "a"), Resolved, ts)
	g.Observe(node(Device, "d", "a"), node(IP, "1.2.3.4", "b"), Connected, ts) // a→b: kiracı sınırı
	if st := g.Stats(); st.Edges != 0 || st.Dropped != 2 {
		t.Fatalf("iki gözlem de reddedilmeli: %+v", st)
	}
	// Sınırdaki kimlik kabul edilir.
	g.Observe(node(Device, "d", "a"), node(Domain, string(long[:DefaultLimits().MaxIDLen]), "a"), Resolved, ts)
	if g.Stats().Edges != 1 {
		t.Fatal("sınırdaki kimlik kabul edilmeli")
	}
	checkInvariants(t, g)
}

// Sweep: olay-zamanı eski VE sunucu-saatiyle eski kenarlar kaldırılır; ileri tarihli olay
// zamanıyla sabitlenmiş ama sunucu-saatiyle eski kenar da süpürülür.
func TestSweepUsesServerClockToo(t *testing.T) {
	g := New()
	clock := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return clock }
	future := clock.Add(10 * 365 * 24 * time.Hour) // cihaz ileri tarihli olay yollar
	g.Observe(node(Device, "d", "a"), node(Domain, "pinned.example", "a"), Resolved, future)
	g.Observe(node(Device, "d", "a"), node(Domain, "old.example", "a"), Resolved, clock.Add(-48*time.Hour))
	clock = clock.Add(40 * 24 * time.Hour)
	g.Observe(node(Device, "d", "a"), node(Domain, "fresh.example", "a"), Resolved, clock)

	// Prune (yalnız olay-zamanı): ileri tarihli kenar SABİT kalırdı.
	if removed := g.Prune(clock.Add(-30 * 24 * time.Hour)); removed != 1 {
		t.Fatalf("Prune yalnız olay-zamanı eskiyi atmalı: %d", removed)
	}
	// Sweep: sunucu saatiyle 40 gün eski "pinned" kenarı da atar; taze kalır.
	if removed := g.Sweep(clock.Add(-30 * 24 * time.Hour)); removed != 1 {
		t.Fatalf("Sweep ileri tarihli sabitlenmiş kenarı atmalı: %d", removed)
	}
	if got := g.Targets(node(Device, "d", "a"), Resolved); len(got) != 1 || got[0].ID != "fresh.example" {
		t.Fatalf("yalnız taze kenar kalmalı: %+v", got)
	}
	if st := g.Stats(); st.Pruned != 2 {
		t.Fatalf("Pruned sayacı 2 olmalı: %+v", st)
	}
	checkInvariants(t, g)
}

// NodesByKindFor tam kiracı eşleşmesi: boş kiracı "hepsi" ANLAMINA GELMEZ.
func TestNodesByKindForExactTenant(t *testing.T) {
	g := New()
	ts := time.Unix(1_700_000_000, 0)
	g.Observe(node(Process, "pa", "a"), node(IP, "1.1.1.1", "a"), Connected, ts)
	g.Observe(node(Process, "pb", "b"), node(IP, "2.2.2.2", "b"), Connected, ts)
	g.Observe(node(Process, "pn", ""), node(IP, "3.3.3.3", ""), Connected, ts)
	if got := g.NodesByKindFor(Process, "a"); len(got) != 1 || got[0].ID != "pa" {
		t.Fatalf("a: %+v", got)
	}
	if got := g.NodesByKindFor(Process, ""); len(got) != 1 || got[0].ID != "pn" {
		t.Fatalf("boş kiracı yalnız kiracısız düğümleri eşlemeli: %+v", got)
	}
	if got := g.NodesByKindFor(Process, "zzz"); len(got) != 0 {
		t.Fatalf("bilinmeyen kiracı boş: %+v", got)
	}
	if got := g.NodesByKind(Process); len(got) != 3 {
		t.Fatalf("NodesByKind tümünü döner (platform yolu): %+v", got)
	}
}
