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
	"container/list"
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

// Node, graf düğümüdür (tür + kimlik + kiracı). Karşılaştırılabilir olduğundan map
// anahtarı olarak kullanılır. Tenant, çok-kiracılı izolasyonu SAĞLAR: farklı kiracıların
// aynı kimlikli (ör. paylaşılan IP/hash) düğümleri AYRI anahtarlardır → kenarlar kiracı
// sınırını geçemez ve bir (tenant,kind,id) sorgusu yalnız o kiracının komşularını döner.
// Tenant boşsa tek-kiracılı/eski davranış (tüm düğümler aynı kiracıda). JSON'da gizlidir
// (API şekli {Kind,ID} korunur) — kiracı yanıtta sızdırılmaz.
type Node struct {
	Kind   Kind
	ID     string
	Tenant string `json:"-"`
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

	// Dahili: sunucu-saatiyle son gözlem anı (TTL süpürmesi için; LastSeen cihaz-kaynaklı olay
	// zamanıdır ve ileri tarihli olay kenarı kalıcı sabitleyebilirdi) ve kiracı LRU listesindeki yeri.
	seen time.Time
	elem *list.Element
	// owner, kenarı kabul ettiren cihazdır (cihaz başına bütçe için; boş = atfedilmemiş).
	owner string
}

// ownerKey, cihaz başına bütçenin anahtarıdır (kiracı + cihaz kimliği).
type ownerKey struct{ tenant, id string }

type edgeKey struct {
	to  Node
	rel Relation
}

// Limits, grafın SERT bellek tavanlarıdır. Girdi (cihaz-kontrollü alan adı,
// IP, süreç adı) sınırsız çeşitlilikte olabileceğinden graf büyümesi iki katmanda tavanlıdır:
//   - kiracı BAŞINA kenar/düğüm tavanı: eskiden-yeniye (LRU) tahliye yalnız o kiracının
//     kenarlarını etkiler;
//   - cihaz BAŞINA kenar bütçesi (MaxEdgesPerDevice): ele geçirilmiş tek bir ajan benzersiz
//     alan adı/IP seliyle kiracı tavanını doldurup diğer cihazların (ve kendi ESKİ C2)
//     kenarlarını LRU ile tahliye ettiremez. Bütçesi dolan cihazın YENİ kenarları hiçbir şey
//     tahliye edilmeden düşürülür ve sayılır (Stats.DeviceDropped); mevcut kenarlar TTL
//     süpürmesine (pencere) kadar korunur.
//
// Sıfır/negatif alan varsayılanı alır.
type Limits struct {
	MaxEdgesPerTenant int // kiracı başına kenar tavanı
	MaxNodesPerTenant int // kiracı başına (en az bir kenara bağlı) düğüm tavanı
	MaxEdgesPerDevice int // cihaz başına (TTL penceresi içinde) azami benzersiz kenar; aşan YENİ kenar düşer
	MaxIDLen          int // düğüm kimliği azami uzunluğu (bayt); aşan gözlem reddedilir
}

// DefaultLimits, makul üretim varsayılanlarını döner.
func DefaultLimits() Limits {
	return Limits{MaxEdgesPerTenant: 100_000, MaxNodesPerTenant: 100_000, MaxEdgesPerDevice: 10_000, MaxIDLen: 256}
}

func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxEdgesPerTenant <= 0 {
		l.MaxEdgesPerTenant = d.MaxEdgesPerTenant
	}
	if l.MaxNodesPerTenant <= 0 {
		l.MaxNodesPerTenant = d.MaxNodesPerTenant
	}
	if l.MaxEdgesPerDevice <= 0 {
		l.MaxEdgesPerDevice = d.MaxEdgesPerDevice
	}
	if l.MaxIDLen <= 0 {
		l.MaxIDLen = d.MaxIDLen
	}
	return l
}

// Stats, grafın anlık boyutu ve kümülatif sayaçlarıdır (/metrics için).
type Stats struct {
	Edges         int
	Nodes         int
	Dropped       int64 // tavan/uzunluk/çapraz-kiracı/cihaz-bütçesi nedeniyle reddedilen gözlemler
	DeviceDropped int64 // Dropped'ın alt kümesi: cihaz bütçesi dolduğu için düşen YENİ kenarlar (sel göstergesi)
	Evicted       int64 // kiracı tavanı aşılınca LRU ile atılan kenarlar
	Pruned        int64 // TTL süpürmesiyle atılan kenarlar
}

// maxEvictPerObserve, tek bir yeni-kenar kabulünde yapılabilecek azami LRU tahliyesidir
// (kötü niyetli girdinin tek gözlemle uzun tahliye döngüsü yaratmasını sınırlar); aşılırsa
// gözlem reddedilir (fail-closed).
const maxEvictPerObserve = 8

// Graph, varlık grafıdır (düğümler kiracı etiketlidir; kiracı sınırı Node.Tenant ile sağlanır).
// Eşzamanlı kullanım için güvenlidir; bellek kiracı başına Limits ile tavanlıdır.
type Graph struct {
	mu   sync.RWMutex
	out  map[Node]map[edgeKey]*Edge // ileri komşuluk
	in   map[Node]map[edgeKey]*Edge // ters komşuluk (geri sorgular)
	now  func() time.Time
	size int

	lim        Limits
	lru        map[string]*list.List // kiracı → kenar listesi (ön = en son gözlenen)
	deg        map[Node]int          // düğüme bağlı kenar sayısı (giren+çıkan)
	tenNodes   map[string]int        // kiracı → düğüm sayısı (deg>0)
	ownerEdges map[ownerKey]int      // (kiracı,cihaz) → bu cihazın kabul ettirdiği canlı kenar sayısı

	dropped, evicted, pruned, devDropped int64
}

// New, boş bir graf oluşturur (varsayılan Limits ile).
func New() *Graph {
	return &Graph{
		out:        map[Node]map[edgeKey]*Edge{},
		in:         map[Node]map[edgeKey]*Edge{},
		now:        time.Now,
		lim:        DefaultLimits(),
		lru:        map[string]*list.List{},
		deg:        map[Node]int{},
		tenNodes:   map[string]int{},
		ownerEdges: map[ownerKey]int{},
	}
}

// SetLimits, tavanları ayarlar (başlangıçta, trafik başlamadan önce çağrılır). Sıfır alan
// varsayılana döner. Mevcut kenarlar hemen tahliye edilmez; yeni kabullerde uygulanır.
func (g *Graph) SetLimits(l Limits) {
	g.mu.Lock()
	g.lim = l.normalized()
	g.mu.Unlock()
}

// Stats, anlık boyut ve kümülatif sayaçları döner.
func (g *Graph) Stats() Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Stats{Edges: g.size, Nodes: len(g.deg), Dropped: g.dropped, Evicted: g.evicted, Pruned: g.pruned, DeviceDropped: g.devDropped}
}

// Observe, from→to (rel) ilişkisini kaydeder veya var olanı günceller (LastSeen,
// Count). ts sıfırsa şimdiki zaman kullanılır. Aynı kenarın tekrar gözlemi yeni
// düğüm/kenar YARATMAZ; sayaç ve son-görülme güncellenir (idempotent üst-yazım).
//
// Sınırlar: uçları farklı kiracılara ait kenar (kiracı sınırını geçemez), aşırı
// uzun kimlik ya da tavan yüzünden yer açılamayan kenar REDDEDİLİR (sayılır). Yeni kenar
// kiracı tavanını aşacaksa o kiracının en eski-gözlenen kenarı (LRU) tahliye edilir.
func (g *Graph) Observe(from, to Node, rel Relation, ts time.Time) {
	owner := ""
	if from.Kind == Device {
		owner = from.ID // cihaz-kaynaklı kenar kendi cihazına atfedilir
	}
	g.ObserveBy(owner, from, to, rel, ts)
}

// ObserveBy, Observe gibidir; ek olarak YENİ kenarı owner cihazına atfeder ve cihaz başına
// bütçeyi (Limits.MaxEdgesPerDevice) uygular: bütçesi dolu cihazın yeni kenarı hiçbir şey
// tahliye edilmeden düşürülür ve sayılır (başka cihazların ve cihazın kendi önceki
// kenarlarının sel ile atılması engellenir). owner boşsa yalnız kiracı tavanları geçerlidir.
// Mevcut bir kenarın tekrar gözlemi sahibini değiştirmez ve bütçe harcamaz.
func (g *Graph) ObserveBy(owner string, from, to Node, rel Relation, ts time.Time) {
	if ts.IsZero() {
		ts = g.now()
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if from.Tenant != to.Tenant || len(from.ID) > g.lim.MaxIDLen || len(to.ID) > g.lim.MaxIDLen {
		g.dropped++
		return
	}
	fk := edgeKey{to: to, rel: rel}
	e := g.out[from][fk]
	if e == nil {
		if owner != "" && g.ownerEdges[ownerKey{from.Tenant, owner}] >= g.lim.MaxEdgesPerDevice {
			g.dropped++
			g.devDropped++
			return
		}
		if !g.admit(from, to) {
			g.dropped++
			return
		}
		if g.out[from] == nil {
			g.out[from] = map[edgeKey]*Edge{}
		}
		e = &Edge{From: from, To: to, Rel: rel, FirstSeen: ts, LastSeen: ts, Count: 0, owner: owner}
		g.out[from][fk] = e
		bk := edgeKey{to: from, rel: rel}
		if g.in[to] == nil {
			g.in[to] = map[edgeKey]*Edge{}
		}
		g.in[to][bk] = e // ters yönde AYNI kenar örneği (paylaşımlı)
		g.size++
		g.addDeg(from)
		g.addDeg(to)
		e.elem = g.tenantList(from.Tenant).PushFront(e)
		if owner != "" {
			g.ownerEdges[ownerKey{from.Tenant, owner}]++
		}
	} else {
		g.tenantList(from.Tenant).MoveToFront(e.elem)
	}
	e.seen = g.now()
	e.Count++
	if ts.After(e.LastSeen) {
		e.LastSeen = ts
	}
	if ts.Before(e.FirstSeen) {
		e.FirstSeen = ts
	}
}

// tenantList, kiracının LRU listesini döner (yoksa oluşturur). Kilit altında çağrılır.
func (g *Graph) tenantList(tenant string) *list.List {
	l := g.lru[tenant]
	if l == nil {
		l = list.New()
		g.lru[tenant] = l
	}
	return l
}

func (g *Graph) addDeg(n Node) {
	if g.deg[n] == 0 {
		g.tenNodes[n.Tenant]++
	}
	g.deg[n]++
}

func (g *Graph) decDeg(n Node) {
	g.deg[n]--
	if g.deg[n] <= 0 {
		delete(g.deg, n)
		if g.tenNodes[n.Tenant]--; g.tenNodes[n.Tenant] <= 0 {
			delete(g.tenNodes, n.Tenant)
		}
	}
}

// admit, from→to YENİ kenarı için kiracı kovasında yer açar (gerekirse LRU tahliyesiyle).
// Yer açılamazsa false (fail-closed). Kilit altında çağrılır.
func (g *Graph) admit(from, to Node) bool {
	t := from.Tenant
	l := g.tenantList(t)
	fits := func() bool {
		newNodes := 0
		if g.deg[from] == 0 {
			newNodes++
		}
		if to != from && g.deg[to] == 0 {
			newNodes++
		}
		return l.Len() < g.lim.MaxEdgesPerTenant && g.tenNodes[t]+newNodes <= g.lim.MaxNodesPerTenant
	}
	for i := 0; i < maxEvictPerObserve; i++ {
		if fits() {
			return true
		}
		back := l.Back()
		if back == nil {
			break
		}
		g.removeEdge(back.Value.(*Edge))
		g.evicted++
	}
	return fits()
}

// removeEdge, kenarı tüm yapılardan çıkarır (komşuluklar, LRU, düğüm sayaçları). Kilit altında.
func (g *Graph) removeEdge(e *Edge) {
	if m := g.out[e.From]; m != nil {
		delete(m, edgeKey{to: e.To, rel: e.Rel})
		if len(m) == 0 {
			delete(g.out, e.From)
		}
	}
	if m := g.in[e.To]; m != nil {
		delete(m, edgeKey{to: e.From, rel: e.Rel})
		if len(m) == 0 {
			delete(g.in, e.To)
		}
	}
	if e.elem != nil {
		if l := g.lru[e.From.Tenant]; l != nil {
			l.Remove(e.elem)
			if l.Len() == 0 {
				delete(g.lru, e.From.Tenant)
			}
		}
		e.elem = nil
	}
	if e.owner != "" {
		k := ownerKey{e.From.Tenant, e.owner}
		if g.ownerEdges[k]--; g.ownerEdges[k] <= 0 {
			delete(g.ownerEdges, k)
		}
	}
	g.size--
	g.decDeg(e.From)
	g.decDeg(e.To)
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

// TargetsAny, (kind,id) eşleşen TÜM kiracı-düğümlerinin hedeflerini birleştirir —
// YALNIZ platform admini (kiracısız) için. Kiracıya bağlı çağıran Targets (kiracı-anahtarlı
// Node) kullanmalıdır; bu, kiracı sınırını AŞAR (kasıtlı: platform tümünü görür).
func (g *Graph) TargetsAny(kind Kind, id string, rel Relation) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return collectAny(g.out, kind, id, rel, func(e *Edge) Node { return e.To })
}

// SourcesAny, (kind,id) eşleşen TÜM kiracı-düğümlerinin kaynaklarını birleştirir —
// YALNIZ platform admini için (kiracı sınırını aşar).
func (g *Graph) SourcesAny(kind Kind, id string, rel Relation) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return collectAny(g.in, kind, id, rel, func(e *Edge) Node { return e.From })
}

// FeaturesAny, (kind,id) eşleşen TÜM kiracı-düğümlerinin yapısal özelliklerini toplar
// — YALNIZ platform admini için.
func (g *Graph) FeaturesAny(kind Kind, id string, rareThreshold int) (fanOut, fanIn, rareEdges int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for n, m := range g.out {
		if n.Kind != kind || n.ID != id {
			continue
		}
		for _, e := range m {
			fanOut++
			if e.Count <= rareThreshold {
				rareEdges++
			}
		}
	}
	for n, m := range g.in {
		if n.Kind != kind || n.ID != id {
			continue
		}
		fanIn += len(m)
	}
	return
}

// collectAny, komşuluk haritasında (kind,id) eşleşen HER kiracı-düğümünün rel'e uyan
// kenarlarını birleştirir; sonucu tekilleştirip kararlı sıralar (platform admini yolu).
func collectAny(adj map[Node]map[edgeKey]*Edge, kind Kind, id string, rel Relation, pick func(*Edge) Node) []Node {
	seen := map[Node]bool{}
	var out []Node
	for n, m := range adj {
		if n.Kind != kind || n.ID != id {
			continue
		}
		for k, e := range m {
			if rel != "" && k.rel != rel {
				continue
			}
			nn := pick(e)
			if !seen[nn] {
				seen[nn] = true
				out = append(out, nn)
			}
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
	return g.removeWhere(func(e *Edge) bool { return e.LastSeen.Before(before) })
}

// Sweep, TTL süpürmesidir: hem olay-zamanı (LastSeen) hem SUNUCU-saatiyle son gözlem anı
// (seen) cutoff'tan eski kenarları kaldırır. Sunucu saati koşulu, ileri tarihli (cihaz-kontrollü)
// olay zamanıyla bir kenarın süresiz sabitlenmesini engeller. app'in periyodik bakım döngüsü
// bunu çağırır (Prune'un üretimde çağıranı yoktu → graf yalnız büyüyordu).
func (g *Graph) Sweep(cutoff time.Time) int {
	return g.removeWhere(func(e *Edge) bool { return e.LastSeen.Before(cutoff) || e.seen.Before(cutoff) })
}

// removeWhere, koşulu sağlayan kenarları kaldırır ve Pruned sayacını artırır.
func (g *Graph) removeWhere(pred func(*Edge) bool) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	var victims []*Edge
	for _, m := range g.out {
		for _, e := range m {
			if pred(e) {
				victims = append(victims, e)
			}
		}
	}
	for _, e := range victims {
		g.removeEdge(e)
	}
	g.pruned += int64(len(victims))
	return len(victims)
}

// NodesByKindFor, belirtilen türdeki düğümlerden YALNIZ verilen kiracıya ait olanları döner
// (tam eşleşme: boş kiracı yalnız boş-kiracılı düğümleri eşler, "hepsi" anlamına GELMEZ).
// Kiracıya bağlı çağıranlar (hunting vb.) bunu kullanmalıdır; NodesByKind kiracı sınırını
// AŞAR ve yalnız platform admini yolunda kullanılmalıdır.
func (g *Graph) NodesByKindFor(kind Kind, tenant string) []Node {
	var out []Node
	for _, n := range g.NodesByKind(kind) {
		if n.Tenant == tenant {
			out = append(out, n)
		}
	}
	return out
}

// NodesByKind, belirtilen türdeki TÜM kiracıların düğümlerini döner — kiracı sınırını AŞAR;
// yalnız platform admini yolunda kullanın (kiracıya bağlı çağıran için NodesByKindFor).
func (g *Graph) NodesByKind(kind Kind) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	seen := map[Node]bool{}
	var out []Node
	for n := range g.out {
		if n.Kind == kind && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for n := range g.in {
		if n.Kind == kind && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// OutEdges, belirtilen düğümden çıkan tüm kenarları döner.
func (g *Graph) OutEdges(n Node) []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	m := g.out[n]
	if len(m) == 0 {
		return nil
	}
	out := make([]Edge, 0, len(m))
	for _, e := range m {
		out = append(out, *e)
	}
	return out
}
