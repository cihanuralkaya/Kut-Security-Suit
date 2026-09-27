package entitygraph

import (
	"testing"
	"time"
)

func dev(id string) Node  { return Node{Kind: Device, ID: id} }
func hash(id string) Node { return Node{Kind: Hash, ID: id} }
func ip(id string) Node   { return Node{Kind: IP, ID: id} }
func usr(id string) Node  { return Node{Kind: User, ID: id} }

// Çok-kiracılı izolasyon: aynı IP'ye iki kiracının cihazı bağlansa bile, bir kiracının
// (tenant-anahtarlı) pivotu diğer kiracının cihazını GÖRMEZ; platform (Any) birleşik görür.
func TestPivotTenantIsolation(t *testing.T) {
	g := New()
	ts := time.Now()
	shared := "8.8.8.8"
	// t1 cihazı ve t2 cihazı AYNI IP'ye bağlanır.
	g.Observe(Node{Kind: Device, ID: "d-acme", Tenant: "acme"}, Node{Kind: IP, ID: shared, Tenant: "acme"}, Connected, ts)
	g.Observe(Node{Kind: Device, ID: "d-globex", Tenant: "globex"}, Node{Kind: IP, ID: shared, Tenant: "globex"}, Connected, ts)

	// acme'nin IP'sinin kaynakları YALNIZ acme cihazı olmalı (globex sızmaz).
	acme := g.Sources(Node{Kind: IP, ID: shared, Tenant: "acme"}, Connected)
	if len(acme) != 1 || acme[0].ID != "d-acme" {
		t.Fatalf("acme IP kaynağı yalnız d-acme olmalı: %+v", acme)
	}
	globex := g.Sources(Node{Kind: IP, ID: shared, Tenant: "globex"}, Connected)
	if len(globex) != 1 || globex[0].ID != "d-globex" {
		t.Fatalf("globex IP kaynağı yalnız d-globex olmalı: %+v", globex)
	}
	// Kiracısız (eski) anahtar hiçbir şey görmez (tüm düğümler kiracı-etiketli).
	if none := g.Sources(Node{Kind: IP, ID: shared}, Connected); len(none) != 0 {
		t.Fatalf("kiracısız anahtar kiracı-etiketli düğümleri görmemeli: %+v", none)
	}
	// Platform (Any) birleşik görür: her iki cihaz da.
	all := g.SourcesAny(IP, shared, Connected)
	if len(all) != 2 {
		t.Fatalf("SourcesAny her iki kiracının cihazını görmeli: %+v", all)
	}
	// FeaturesAny fan-in = 2 (iki cihaz), tenant-scoped fan-in = 1.
	if _, fanIn, _ := g.Features(Node{Kind: IP, ID: shared, Tenant: "acme"}, 1); fanIn != 1 {
		t.Fatalf("acme fan-in 1 olmalı: %d", fanIn)
	}
	if _, fanIn, _ := g.FeaturesAny(IP, shared, 1); fanIn != 2 {
		t.Fatalf("Any fan-in 2 olmalı: %d", fanIn)
	}
}

func TestPivotHashAcrossDevices(t *testing.T) {
	g := New()
	h := hash("sha:abc")
	// İki farklı cihaz AYNI hash'i çalıştırdı.
	g.Observe(dev("pc-1"), h, Ran, time.Time{})
	g.Observe(dev("pc-2"), h, Ran, time.Time{})
	// pc-1 aynı hash'i tekrar çalıştırdı → yeni kenar YARATMAZ, sayaç artar.
	g.Observe(dev("pc-1"), h, Ran, time.Time{})

	if g.Size() != 2 {
		t.Fatalf("2 benzersiz kenar beklenirdi, %d", g.Size())
	}
	// "Bu hash başka hangi cihazlarda çalıştı?" → pc-1, pc-2.
	got := g.Sources(h, Ran)
	if len(got) != 2 || got[0] != dev("pc-1") || got[1] != dev("pc-2") {
		t.Fatalf("hash için kaynak cihazlar yanlış: %+v", got)
	}
	// Ters yön: pc-1 hangi hash'leri çalıştırdı?
	tg := g.Targets(dev("pc-1"), Ran)
	if len(tg) != 1 || tg[0] != h {
		t.Fatalf("pc-1'in hedefleri yanlış: %+v", tg)
	}
}

func TestPivotIPPeers(t *testing.T) {
	g := New()
	bad := ip("203.0.113.9")
	g.Observe(dev("pc-1"), bad, Connected, time.Time{})
	g.Observe(dev("pc-3"), bad, Connected, time.Time{})
	peers := g.Sources(bad, Connected)
	if len(peers) != 2 {
		t.Fatalf("IP ile konuşan 2 cihaz beklenirdi: %+v", peers)
	}
	// Farklı ilişki türü sızmamalı: bu IP'ye 'ran' yok.
	if n := g.Sources(bad, Ran); len(n) != 0 {
		t.Fatalf("IP'ye 'ran' ilişkisi olmamalı: %+v", n)
	}
}

func TestReachableMultiHop(t *testing.T) {
	g := New()
	// user -logged_in-> pc-1 -ran-> hash -... ; user -logged_in-> pc-1 -connected-> ip
	g.Observe(usr("alice"), dev("pc-1"), LoggedIn, time.Time{})
	g.Observe(dev("pc-1"), hash("sha:abc"), Ran, time.Time{})
	g.Observe(dev("pc-1"), ip("203.0.113.9"), Connected, time.Time{})

	// 1 adım: yalnız pc-1.
	if n := g.Reachable(usr("alice"), 1); len(n) != 1 || n[0] != dev("pc-1") {
		t.Fatalf("1-adım ulaşılabilir yanlış: %+v", n)
	}
	// 2 adım: pc-1 + hash + ip.
	n := g.Reachable(usr("alice"), 2)
	if len(n) != 3 {
		t.Fatalf("2-adım 3 düğüm beklenirdi: %+v", n)
	}
}

func TestFeatures(t *testing.T) {
	g := New()
	d := dev("pc-1")
	// pc-1 üç farklı IP'ye bağlandı (fan-out=3); biri iki kez (sık), ikisi bir kez (nadir).
	g.Observe(d, ip("a"), Connected, time.Time{})
	g.Observe(d, ip("a"), Connected, time.Time{}) // a: 2 gözlem
	g.Observe(d, ip("b"), Connected, time.Time{}) // b: 1 gözlem (nadir)
	g.Observe(d, ip("c"), Connected, time.Time{}) // c: 1 gözlem (nadir)
	// usr → pc-1 (fan-in=1).
	g.Observe(usr("alice"), d, LoggedIn, time.Time{})

	fanOut, fanIn, rare := g.Features(d, 1) // rareThreshold=1 → Count<=1 nadir
	if fanOut != 3 {
		t.Fatalf("fan-out 3 beklenirdi: %d", fanOut)
	}
	if fanIn != 1 {
		t.Fatalf("fan-in 1 beklenirdi: %d", fanIn)
	}
	if rare != 2 {
		t.Fatalf("nadir kenar 2 beklenirdi (b, c): %d", rare)
	}
}

func TestPruneOldEdges(t *testing.T) {
	g := New()
	old := time.Unix(1_000_000, 0)
	recent := time.Unix(2_000_000, 0)
	g.Observe(dev("pc-1"), hash("h1"), Ran, old)
	g.Observe(dev("pc-2"), hash("h2"), Ran, recent)

	removed := g.Prune(time.Unix(1_500_000, 0))
	if removed != 1 {
		t.Fatalf("1 eski kenar budanmalıydı, %d", removed)
	}
	if g.Size() != 1 {
		t.Fatalf("budamadan sonra 1 kenar kalmalı, %d", g.Size())
	}
	// Eski kenarın ters-komşuluk girişi de temizlenmeli.
	if n := g.Sources(hash("h1"), Ran); len(n) != 0 {
		t.Fatalf("budanan kenarın kaynağı kalmamalı: %+v", n)
	}
	if n := g.Sources(hash("h2"), Ran); len(n) != 1 {
		t.Fatalf("güncel kenar korunmalı: %+v", n)
	}
}
