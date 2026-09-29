package aisec

// causality.go — AG-06: Agent Causality Graph (KUT-AI-SEC-006/007/009). Veri-zemininin
// asıl amacı: agent olaylarını (kimlik, delegation, tool/memory read/write, influence) bir
// nedensellik grafına örmek ve TAINT'i graf boyunca yayarak AI-agent saldırı zincirini
// uçtan-uca tespit etmek — ör. `untrusted context → agent → credential read → external
// write` (indirect prompt-injection → credential access → exfiltration). Deterministik.

// NodeKind, graf düğüm türüdür.
type NodeKind string

const (
	KindAgent      NodeKind = "agent"
	KindTool       NodeKind = "tool"
	KindMemory     NodeKind = "memory"
	KindContext    NodeKind = "context"    // genel dış/iç veri bağlamı
	KindCredential NodeKind = "credential" // hassas kaynak (sır/kimlik-bilgisi)
	KindExternal   NodeKind = "external"   // dış sink (exfil kanalı: HTTP/DNS vb.)
)

// node, bir graf düğümüdür.
type node struct {
	ID    string
	Kind  NodeKind
	Trust TrustLevel
}

// edge, taint TAŞIYAN yönlü bir kenardır (From → To): From, To'ya akar; To'nun etkin
// güveni en fazla From'unki kadar düşer.
type edge struct{ from, to string }

// writeEdge, bir agent'ın bir sink'e YAZMA (egress) kenarıdır — taint yaymaz, egress
// tespiti için kullanılır.
type writeEdge struct{ agent, sink string }

// Varsayılan sınırlar: graf, HTTP'den beslenen bir veri-zemini olduğundan (per-request
// cap yok, yalnız gövde-boyutu sınırı) süreç-ömrü boyunca SINIRSIZ büyümemelidir —
// aksi halde bellek tükenmesi + O(N·E) `Findings()` yeniden-hesabı ile CPU DoS. Bu üst
// sınırlar + kenar dedupe'si büyümeyi sabitler (kaynak-tükenmesi savunması).
const (
	defaultMaxNodes = 20000
	defaultMaxEdges = 50000
)

// CausalityGraph, agent nedensellik grafıdır. Deterministik; eşzamanlı kullanım için
// harici senkronizasyon gerekir (tek analiz-thread'i varsayılır — bkz. Service kilidi).
// Düğüm/kenar sayıları üst-sınırlıdır: kenarlar dedupe edilir (aynı gözlem tekrarı
// büyütmez) ve sınır aşılırsa en eski (FIFO) düşürülür.
type CausalityGraph struct {
	nodes     map[string]node
	nodeOrder []string // FIFO ekleme sırası (düğüm eviction'ı için)
	taint     []edge   // taint taşıyan kenarlar (reads/influences/delegates), tekilleştirilmiş
	taintSeen map[edge]struct{}
	writes    []writeEdge // egress (agent → sink), tekilleştirilmiş
	writeSeen map[writeEdge]struct{}
	maxNodes  int
	maxEdges  int
}

// NewCausalityGraph, varsayılan üst-sınırlarla bir graf oluşturur.
func NewCausalityGraph() *CausalityGraph {
	return &CausalityGraph{
		nodes:     map[string]node{},
		taintSeen: map[edge]struct{}{},
		writeSeen: map[writeEdge]struct{}{},
		maxNodes:  defaultMaxNodes,
		maxEdges:  defaultMaxEdges,
	}
}

// AddNode, bir düğüm ekler/günceller. Yeni bir id kapasiteyi aşarsa en eski eklenen
// düğüm düşürülür (FIFO); mevcut id'nin güncellenmesi sıralamayı değiştirmez.
func (g *CausalityGraph) AddNode(id string, kind NodeKind, trust TrustLevel) {
	if id == "" {
		return
	}
	if _, exists := g.nodes[id]; !exists {
		if g.maxNodes > 0 && len(g.nodes) >= g.maxNodes {
			// En eski düğümü düş (FIFO). Ona bağlı kenarlar EffectiveTrust/readsOfKind'da
			// çözülmeyip atlanır — zararsız (evict edilmiş düğüm için bulgu üretmez).
			old := g.nodeOrder[0]
			g.nodeOrder = g.nodeOrder[1:]
			delete(g.nodes, old)
		}
		g.nodeOrder = append(g.nodeOrder, id)
	}
	g.nodes[id] = node{ID: id, Kind: kind, Trust: trust}
}

// addTaint, bir taint kenarını tekilleştirerek ekler; kapasite aşılırsa en eskiyi düşürür.
func (g *CausalityGraph) addTaint(e edge) {
	if _, dup := g.taintSeen[e]; dup {
		return // aynı gözlem tekrarı → büyütme (amplifikasyon önlenir)
	}
	if g.maxEdges > 0 && len(g.taint) >= g.maxEdges {
		old := g.taint[0]
		g.taint = g.taint[1:]
		delete(g.taintSeen, old)
	}
	g.taint = append(g.taint, e)
	g.taintSeen[e] = struct{}{}
}

// AddRead, "agent, source'u okur" — taint source → agent yönünde akar (INV-AG-001/005).
func (g *CausalityGraph) AddRead(agent, source string) { g.addTaint(edge{source, agent}) }

// AddInfluence, "from, to'yu etkiler" — taint from → to.
func (g *CausalityGraph) AddInfluence(from, to string) { g.addTaint(edge{from, to}) }

// AddDelegate, "delegator, delegatee'yi delege eder" — delegatee güveni delegatörünkini
// AŞAMAZ (INV-AG-003 ruhu; taint delegator → delegatee).
func (g *CausalityGraph) AddDelegate(delegator, delegatee string) {
	g.addTaint(edge{delegator, delegatee})
}

// AddWrite, "agent, sink'e yazar" — egress kenarı (exfil tespiti için). Tekilleştirilir;
// kapasite aşılırsa en eski düşürülür.
func (g *CausalityGraph) AddWrite(agent, sink string) {
	w := writeEdge{agent, sink}
	if _, dup := g.writeSeen[w]; dup {
		return
	}
	if g.maxEdges > 0 && len(g.writes) >= g.maxEdges {
		old := g.writes[0]
		g.writes = g.writes[1:]
		delete(g.writeSeen, old)
	}
	g.writes = append(g.writes, w)
	g.writeSeen[w] = struct{}{}
}

// EffectiveTrust, taint'i graf boyunca yayarak her düğümün ETKİN güven düzeyini hesaplar
// (fixpoint gevşetme; döngülere dayanıklı). Bir düğüm, kendisine taint-kenarıyla akan
// herhangi bir düğümden daha güvenilir OLAMAZ (en kirli kazanır, INV-AG-001).
func (g *CausalityGraph) EffectiveTrust() map[string]TrustLevel {
	eff := make(map[string]TrustLevel, len(g.nodes))
	for id, n := range g.nodes {
		eff[id] = n.Trust
	}
	// Fixpoint: en fazla düğüm-sayısı kadar tur (monoton azaldığı için sonlu).
	for i := 0; i < len(g.nodes)+1; i++ {
		changed := false
		for _, e := range g.taint {
			fu, ok1 := eff[e.from]
			tv, ok2 := eff[e.to]
			if !ok1 || !ok2 {
				continue
			}
			if nv := PropagateTrust(tv, fu); nv < tv {
				eff[e.to] = nv
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return eff
}

// ExfilFinding, tespit edilen bir exfiltration riskidir.
type ExfilFinding struct {
	AgentID    string
	Credential string
	Sink       string
	Trust      TrustLevel
}

// DetectExfiltration, INV-AG-004'ün graf-seviyesi tespitidir: etkin güveni Untrusted/
// Tainted'a düşmüş bir agent, bir credential kaynağını OKUYUP bir external sink'e YAZIYORSA
// exfil zinciri olarak işaretlenir (untrusted → credential → external). Deterministik;
// tespit DATA'dır (INV-AG-010) — enforcement §0 zincirinden geçer.
func (g *CausalityGraph) DetectExfiltration() []ExfilFinding {
	eff := g.EffectiveTrust()
	var out []ExfilFinding
	for id, n := range g.nodes {
		if n.Kind != KindAgent || eff[id] > Untrusted {
			continue // yalnız güveni düşmüş agent'lar
		}
		cred := g.readsOfKind(id, KindCredential)
		if cred == "" {
			continue
		}
		sink := g.writesToKind(id, KindExternal)
		if sink == "" {
			continue
		}
		out = append(out, ExfilFinding{AgentID: id, Credential: cred, Sink: sink, Trust: eff[id]})
	}
	return out
}

// readsOfKind, agent'ın verilen türde bir kaynağı okuyup okumadığını döner (ilk eşleşen id).
func (g *CausalityGraph) readsOfKind(agent string, kind NodeKind) string {
	for _, e := range g.taint {
		if e.to == agent {
			if n, ok := g.nodes[e.from]; ok && n.Kind == kind {
				return n.ID
			}
		}
	}
	return ""
}

// writesToKind, agent'ın verilen türde bir sink'e yazıp yazmadığını döner (ilk eşleşen id).
func (g *CausalityGraph) writesToKind(agent string, kind NodeKind) string {
	for _, w := range g.writes {
		if w.agent == agent {
			if n, ok := g.nodes[w.sink]; ok && n.Kind == kind {
				return n.ID
			}
		}
	}
	return ""
}
