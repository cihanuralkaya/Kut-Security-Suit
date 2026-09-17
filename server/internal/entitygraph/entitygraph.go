// Package entitygraph, KUT'un varlık/tehdit grafıdır (§XDR): telemetriden gözlenen
// varlıkları (cihaz, kullanıcı, süreç, dosya, hash, alan adı, IP, sertifika) ve
// aralarındaki ilişkileri (çalıştırdı, bağlandı, çözümledi, oturum açtı, …) tutar.
// Korelasyon ve tehdit-avı (hunting) bunun üstünde "pivot" yapar: "bu hash başka
// hangi cihazlarda çalıştı?", "bu IP ile kim konuştu?" gibi sorular.
//
// Saf Go, sıfır bağımlılık: yönlü bir kenar kümesi + ters komşuluk (geri sorgular
// için) + eşzamanlı erişim güvenliği. Kalıcılık ileri bir fazdır; bu çekirdek
// bellek-içidir ve deterministiktir (AI/GNN katmanları sonradan AYNI grafı okur).
package entitygraph

import (
	"sort"
	"sync"
	"time"
)

// Kind, bir varlık düğümünün türüdür.
type Kind string

const (
	Device  Kind = "device"
	User    Kind = "user"
	Process Kind = "process"
	File    Kind = "file"
	Hash    Kind = "hash"
	Domain  Kind = "domain"
	IP      Kind = "ip"
	Cert    Kind = "cert"
)

// Relation, iki varlık arasındaki yönlü ilişkidir.
type Relation string

const (
	Ran       Relation = "ran"       // device→hash/process, process→file
	Connected Relation = "connected" // device/process→ip
	Resolved  Relation = "resolved"  // device/process→domain, domain→ip
	LoggedIn  Relation = "logged_in" // user→device
	ChildOf   Relation = "child_of"  // process→process
	HasHash   Relation = "has_hash"  // file→hash
)

// Node, graf düğümüdür (tür + kimlik). Karşılaştırılabilir olduğundan map anahtarı
// olarak kullanılır.
type Node struct {
	Kind Kind
	ID   string
}

// Edge, iki düğüm arasındaki gözlenmiş ilişkidir; ilk/son görülme ve gözlem sayısı
// ile birlikte (zaman-serisi pivotu ve gürültü ayıklama için).
type Edge struct {
	From      Node
	To        Node
	Rel       Relation
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

type edgeKey struct {
	to  Node
	rel Relation
}

// Graph, tek bir kiracının varlık grafıdır (çağıran kiracı-kapsamını yönetir).
// Eşzamanlı kullanım için güvenlidir.
type Graph struct {
	mu   sync.RWMutex
	out  map[Node]map[edgeKey]*Edge // ileri komşuluk
	in   map[Node]map[edgeKey]*Edge // ters komşuluk (geri sorgular)
	now  func() time.Time
	size int
}

// New, boş bir graf oluşturur.
func New() *Graph {
	return &Graph{
		out: map[Node]map[edgeKey]*Edge{},
		in:  map[Node]map[edgeKey]*Edge{},
		now: time.Now,
	}
}

// Observe, from→to (rel) ilişkisini kaydeder veya var olanı günceller (LastSeen,
// Count). ts sıfırsa şimdiki zaman kullanılır. Aynı kenarın tekrar gözlemi yeni
// düğüm/kenar YARATMAZ; sayaç ve son-görülme güncellenir (idempotent üst-yazım).
func (g *Graph) Observe(from, to Node, rel Relation, ts time.Time) {
	if ts.IsZero() {
		ts = g.now()
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	fk := edgeKey{to: to, rel: rel}
	if g.out[from] == nil {
		g.out[from] = map[edgeKey]*Edge{}
	}
	e := g.out[from][fk]
	if e == nil {
		e = &Edge{From: from, To: to, Rel: rel, FirstSeen: ts, LastSeen: ts, Count: 0}
		g.out[from][fk] = e
		bk := edgeKey{to: from, rel: rel}
		if g.in[to] == nil {
			g.in[to] = map[edgeKey]*Edge{}
		}
		g.in[to][bk] = e // ters yönde AYNI kenar örneği (paylaşımlı)
		g.size++
	}
	e.Count++
	if ts.After(e.LastSeen) {
		e.LastSeen = ts
	}
	if ts.Before(e.FirstSeen) {
		e.FirstSeen = ts
	}
}

// Size, benzersiz kenar sayısını döner.
func (g *Graph) Size() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.size
}

// Targets, source düğümünden rel ile çıkan kenarların hedeflerini döner (ör. bir
// cihazın çalıştırdığı hash'ler). rel boşsa tüm ilişkiler. Sonuç kararlı sıralıdır.
func (g *Graph) Targets(source Node, rel Relation) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return collect(g.out[source], rel, func(e *Edge) Node { return e.To })
}

// Sources, target düğümüne rel ile GİREN kenarların kaynaklarını döner (ör. bir
// hash'i çalıştıran cihazlar: Sources({Hash,h}, Ran)). rel boşsa tüm ilişkiler.
func (g *Graph) Sources(target Node, rel Relation) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return collect(g.in[target], rel, func(e *Edge) Node { return e.From })
}

// collect, bir komşuluk haritasından rel'e uyan kenarları toplar ve pick ile düğüme
// eşler; sonucu tekilleştirip kararlı sıralar.
func collect(m map[edgeKey]*Edge, rel Relation, pick func(*Edge) Node) []Node {
	seen := map[Node]bool{}
	var out []Node
	for k, e := range m {
		if rel != "" && k.rel != rel {
			continue
		}
		n := pick(e)
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Features, bir düğümün yapısal özelliklerini döner: toplam çıkan (fanOut) ve giren
// (fanIn) kenar sayısı ile nadir kenar sayısı (gözlem sayısı rareThreshold'un altında
// olan az-görülmüş ilişkiler). Yapısal anomali skorlaması (aibrain.ScoreGraph) için
// deterministik ön-hesaptır; ham graf dışarı sızmadan yalnız metrik üretir.
func (g *Graph) Features(n Node, rareThreshold int) (fanOut, fanIn, rareEdges int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, e := range g.out[n] {
		fanOut++
		if e.Count <= rareThreshold {
			rareEdges++
		}
	}
	fanIn = len(g.in[n])
	return
}

// Reachable, start'tan en fazla maxDepth adımda (yönlü, ileri) ulaşılan düğümleri
// döner (start hariç) — çok-adımlı pivot/etki alanı analizi için sınırlı BFS.
func (g *Graph) Reachable(start Node, maxDepth int) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := map[Node]bool{start: true}
	frontier := []Node{start}
	var order []Node
	for d := 0; d < maxDepth && len(frontier) > 0; d++ {
		var next []Node
		for _, n := range frontier {
			for _, e := range g.out[n] {
				if !visited[e.To] {
					visited[e.To] = true
					order = append(order, e.To)
					next = append(next, e.To)
				}
			}
		}
		frontier = next
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].Kind != order[j].Kind {
			return order[i].Kind < order[j].Kind
		}
		return order[i].ID < order[j].ID
	})
	return order
}

// Prune, LastSeen'i before'dan eski olan kenarları kaldırır (bellek/gürültü
// yönetimi). Kaldırılan kenar sayısını döner.
func (g *Graph) Prune(before time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	removed := 0
	for from, m := range g.out {
		for k, e := range m {
			if e.LastSeen.Before(before) {
				delete(m, k)
				delete(g.in[e.To], edgeKey{to: from, rel: e.Rel})
				removed++
				g.size--
			}
		}
		if len(m) == 0 {
			delete(g.out, from)
		}
	}
	return removed
}
