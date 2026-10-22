package entitygraph

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// tek bir (ele geçirilmiş) cihaz benzersiz alan adı seliyle kiracı tavanını doldurup
// diğer cihazların kenarlarını ya da kendi ESKİ C2 kenarını tahliye ettiremez. Yeni kenarlar
// düşer ve sayılır; mevcutlar korunur.
func TestDeviceBudgetFloodCannotEvict(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerTenant: 50_000, MaxNodesPerTenant: 1_000_000, MaxEdgesPerDevice: 1_000})
	base := time.Unix(1_700_000_000, 0)
	x := node(Device, "dev-x", "t")
	y := node(Device, "dev-y", "t")

	// Y'nin meşru kenarları ve X'in İLK C2 kenarı.
	for i := 0; i < 20; i++ {
		g.Observe(y, node(Domain, "ok"+strconv.Itoa(i)+".example", "t"), Resolved, base)
	}
	c2 := node(IP, "203.0.113.66", "t")
	g.Observe(x, c2, Connected, base)

	// X: 1M benzersiz alan adı seli.
	for i := 0; i < 1_000_000; i++ {
		g.Observe(x, node(Domain, "junk"+strconv.Itoa(i)+".evil", "t"), Resolved, base)
	}
	st := g.Stats()
	if st.Evicted != 0 {
		t.Fatalf("sel hiçbir kenarı tahliye ETMEMELİ (düşürmeli): %+v", st)
	}
	if st.Edges != 20+1000 {
		t.Fatalf("X en fazla bütçesi (1000) kadar kenar tutmalı: edges=%d", st.Edges)
	}
	if st.DeviceDropped != int64(1_000_000+1-1000) || st.Dropped < st.DeviceDropped {
		t.Fatalf("düşen kenarlar sayılmalı: %+v", st)
	}
	if got := g.Targets(y, Resolved); len(got) != 20 {
		t.Fatalf("Y'nin kenarları korunmalı: %d", len(got))
	}
	found := false
	for _, n := range g.Targets(x, Connected) {
		if n == c2 {
			found = true
		}
	}
	if !found {
		t.Fatal("X'in ilk C2 kenarı sel ile tahliye edilmemeli")
	}
	checkInvariants(t, g)
}

// Bütçe kenar TEKRAR gözleminde harcanmaz; TTL süpürmesi bütçeyi geri verir (pencere);
// başka cihazın bütçesi bağımsızdır; kiracılar arası da bağımsızdır.
func TestDeviceBudgetWindowAndIsolation(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerDevice: 3})
	base := time.Unix(1_700_000_000, 0)
	x := node(Device, "dev-x", "t")
	for i := 0; i < 3; i++ {
		g.Observe(x, node(Domain, "d"+strconv.Itoa(i), "t"), Resolved, base)
	}
	// Mevcut kenarın tekrarı: bütçe harcamaz, düşmez.
	g.Observe(x, node(Domain, "d0", "t"), Resolved, base.Add(time.Minute))
	if st := g.Stats(); st.DeviceDropped != 0 || st.Edges != 3 {
		t.Fatalf("tekrar gözlem düşmemeli: %+v", st)
	}
	// Yeni kenar: bütçe dolu → düşer.
	g.Observe(x, node(Domain, "d3", "t"), Resolved, base)
	if st := g.Stats(); st.DeviceDropped != 1 || st.Edges != 3 {
		t.Fatalf("bütçe dolu → düşmeli: %+v", st)
	}
	// Aynı cihaz kimliği başka kiracıda AYRI bütçe; başka cihaz AYRI bütçe.
	g.Observe(node(Device, "dev-x", "u"), node(Domain, "z", "u"), Resolved, base)
	g.Observe(node(Device, "dev-y", "t"), node(Domain, "z", "t"), Resolved, base)
	if st := g.Stats(); st.Edges != 5 || st.DeviceDropped != 1 {
		t.Fatalf("bütçeler bağımsız olmalı: %+v", st)
	}
	// TTL süpürmesi bütçeyi geri verir: yeni kenar yeniden kabul edilir.
	if n := g.Sweep(time.Now().Add(24 * time.Hour)); n != 5 {
		t.Fatalf("süpürme 5 kenar atmalı: %d", n)
	}
	g.Observe(x, node(Domain, "d3", "t"), Resolved, time.Now())
	if g.Size() != 1 {
		t.Fatalf("süpürme sonrası bütçe geri gelmeli: %d", g.Size())
	}
	checkInvariants(t, g)
}

// ObserveBy ile atfedilen (ör. süreç soyağacı) kenarlar cihaza sayılır: cihaz süreç-adı
// seliyle de bütçeyi aşamaz.
func TestObserveByChargesOwnerForNonDeviceEdges(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerDevice: 10})
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 100; i++ {
		g.ObserveBy("dev-x", node(Process, "p"+strconv.Itoa(i), "t"), node(Process, "parent", "t"), ChildOf, base)
	}
	if st := g.Stats(); st.Edges != 10 || st.DeviceDropped != 90 {
		t.Fatalf("süreç kenarları da cihaz bütçesine sayılmalı: %+v", st)
	}
	checkInvariants(t, g)
}

// Eşzamanlılık (CI -race ile koşar): paralel gözlem/sorgu/süpürme/istatistik veri yarışı
// ve değişmez ihlali üretmemeli.
func TestGraphConcurrentAccess(t *testing.T) {
	g := New()
	g.SetLimits(Limits{MaxEdgesPerTenant: 500, MaxNodesPerTenant: 800, MaxEdgesPerDevice: 100})
	var wg sync.WaitGroup
	base := time.Now()
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			dev := node(Device, "dev"+strconv.Itoa(w%4), "t"+strconv.Itoa(w%2))
			for i := 0; i < 2000; i++ {
				g.Observe(dev, node(Domain, "d"+strconv.Itoa(i), dev.Tenant), Resolved, base)
				if i%50 == 0 {
					_ = g.Targets(dev, Resolved)
					_ = g.Stats()
					_ = g.NodesByKindFor(Domain, dev.Tenant)
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			g.Sweep(base.Add(-time.Hour))
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	checkInvariants(t, g)
	if g.Size() > 1000 {
		t.Fatalf("kiracı tavanları aşılmamalı: %d", g.Size())
	}
}
