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

// CausalityGraph, agent nedensellik grafıdır. Deterministik; eşzamanlı kullanım için
// harici senkronizasyon gerekir (tek analiz-thread'i varsayılır).
type CausalityGraph struct {
	nodes  map[string]node
	taint  []edge      // taint taşıyan kenarlar (reads/influences/delegates)
	writes []writeEdge // egress (agent → sink)
}

// NewCausalityGraph oluşturur.
func NewCausalityGraph() *CausalityGraph {
	return &CausalityGraph{nodes: map[string]node{}}
}

// AddNode, bir düğüm ekler/günceller.
func (g *CausalityGraph) AddNode(id string, kind NodeKind, trust TrustLevel) {
	if id == "" {
		return
	}
	g.nodes[id] = node{ID: id, Kind: kind, Trust: trust}
}

// AddRead, "agent, source'u okur" — taint source → agent yönünde akar (INV-AG-001/005).
func (g *CausalityGraph) AddRead(agent, source string) {
	g.taint = append(g.taint, edge{source, agent})
}

// AddInfluence, "from, to'yu etkiler" — taint from → to.
func (g *CausalityGraph) AddInfluence(from, to string) { g.taint = append(g.taint, edge{from, to}) }

// AddDelegate, "delegator, delegatee'yi delege eder" — delegatee güveni delegatörünkini
// AŞAMAZ (INV-AG-003 ruhu; taint delegator → delegatee).
func (g *CausalityGraph) AddDelegate(delegator, delegatee string) {
	g.taint = append(g.taint, edge{delegator, delegatee})
}

// AddWrite, "agent, sink'e yazar" — egress kenarı (exfil tespiti için).
func (g *CausalityGraph) AddWrite(agent, sink string) {
	g.writes = append(g.writes, writeEdge{agent, sink})
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
