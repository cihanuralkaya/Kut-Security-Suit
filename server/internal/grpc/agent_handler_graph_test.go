package grpc

import (
	"strconv"
	"testing"
	"time"

	"kut.corp/suite/server/internal/aibrain"
	"kut.corp/suite/server/internal/entitygraph"
	"kut.corp/suite/server/internal/model"
)

// TestObserveGraphFeedsSeqModel, PROCESS soyağacının sekans nadirlik modeline
// root→leaf sırayla PASİF öğrenildiğini doğrular: öğrenilen zincir düşük, hiç
// görülmemiş geçiş yüksek skorlanır (graf bağlı olmasa da model beslenir).
func TestObserveGraphFeedsSeqModel(t *testing.T) {
	m := aibrain.NewSeqModels()
	h := &AgentHandler{seqModel: m} // graf yok, yalnız model
	for i := 0; i < 5; i++ {
		h.observeGraph("pc-1", model.Event{
			Details:    `{"process":"ipconfig.exe","parent_chain":["cmd.exe","explorer.exe"]}`,
			OccurredAt: time.Now(),
		})
	}
	// Öğrenilen zincir (explorer→cmd→ipconfig) düşük skorlanmalı.
	if s := m.Score("", []string{"explorer.exe", "cmd.exe", "ipconfig.exe"}); s.Score > 20 {
		t.Fatalf("öğrenilen zincir düşük skorlanmalı: %v", s.Score)
	}
	// Hiç görülmemiş geçiş (winword→powershell) yüksek skorlanmalı.
	if s := m.Score("", []string{"winword.exe", "powershell.exe"}); s.Score < 80 {
		t.Fatalf("görülmemiş geçiş yüksek skorlanmalı: %v", s.Score)
	}
}

// TestObserveGraphFromEvents, ajan olaylarının varlık/tehdit grafına doğru kenarlar
// beslediğini doğrular: DNS olayı → cihaz→alan (Resolved), ağ bağlantısı → cihaz→IP
// (Connected). Böylece "bu IP ile hangi cihazlar konuştu?" pivotu yanıtlanabilir.
func TestObserveGraphFromEvents(t *testing.T) {
	g := entitygraph.New()
	h := &AgentHandler{graph: g}

	h.observeGraph("pc-1", model.Event{Details: `{"dns":true,"domain":"evil.example"}`, OccurredAt: time.Now()})
	h.observeGraph("pc-1", model.Event{Details: `{"remote_ip":"203.0.113.9","remote_port":443}`, OccurredAt: time.Now()})
	h.observeGraph("pc-2", model.Event{Details: `{"remote_ip":"203.0.113.9"}`, OccurredAt: time.Now()})

	// Pivot: bu IP ile hangi cihazlar konuştu? → pc-1, pc-2.
	peers := g.Sources(entitygraph.Node{Kind: entitygraph.IP, ID: "203.0.113.9"}, entitygraph.Connected)
	if len(peers) != 2 {
		t.Fatalf("IP ile konuşan 2 cihaz beklenirdi: %+v", peers)
	}
	// Pivot: pc-1 hangi alanları çözümledi? → evil.example.
	doms := g.Targets(entitygraph.Node{Kind: entitygraph.Device, ID: "pc-1"}, entitygraph.Resolved)
	if len(doms) != 1 || doms[0].ID != "evil.example" {
		t.Fatalf("pc-1'in çözümlediği alan yanlış: %+v", doms)
	}
}

// TestObserveGraphProcessLineage, PROCESS olayının parent_chain'inden süreç
// soyağacı (ChildOf) kenarlarının kurulduğunu doğrular: "bu süreç neyi başlattı?"
// ve "ebeveyni ne?" pivotları — sekans-nadirliği veri temeli.
func TestObserveGraphProcessLineage(t *testing.T) {
	g := entitygraph.New()
	h := &AgentHandler{graph: g}
	// powershell ← winword ← explorer (en yakın ata önce).
	h.observeGraph("pc-1", model.Event{
		Details:    `{"process":"powershell.exe","parent_chain":["winword.exe","explorer.exe"]}`,
		OccurredAt: time.Now(),
	})
	// "winword.exe neyi başlattı?" → powershell.exe (çocuk = Sources, ChildOf).
	kids := g.Sources(entitygraph.Node{Kind: entitygraph.Process, ID: "winword.exe"}, entitygraph.ChildOf)
	if len(kids) != 1 || kids[0].ID != "powershell.exe" {
		t.Fatalf("winword'ün çocuğu yanlış: %+v", kids)
	}
	// "powershell.exe'nin ebeveyni?" → winword.exe (Targets, ChildOf).
	par := g.Targets(entitygraph.Node{Kind: entitygraph.Process, ID: "powershell.exe"}, entitygraph.ChildOf)
	if len(par) != 1 || par[0].ID != "winword.exe" {
		t.Fatalf("powershell'in ebeveyni yanlış: %+v", par)
	}
}

// TestObserveGraphSafeWithoutGraph, graf bağlı değilken veya bozuk/eksik Details ile
// observeGraph'ın güvenle no-op olduğunu doğrular (panik yok).
func TestObserveGraphSafeWithoutGraph(t *testing.T) {
	(&AgentHandler{}).observeGraph("x", model.Event{Details: `{"domain":"y"}`}) // graf nil
	h := &AgentHandler{graph: entitygraph.New()}
	h.observeGraph("x", model.Event{Details: ``})              // boş Details
	h.observeGraph("x", model.Event{Details: `{bozuk`})        // geçersiz JSON
	h.observeGraph("", model.Event{Details: `{"domain":"y"}`}) // boş cihaz
	if h.graph.Size() != 0 {
		t.Fatalf("geçersiz/eksik girdiler kenar yaratmamalı, size=%d", h.graph.Size())
	}
}

// Z3-03: ajan-kontrollü dizgeler sınırlıdır — aşırı uzun alan adı/süreç adı atlanır, parent_chain
// derinlik tavanında kesilir; graf kiracı tavanıyla sınırlı kalır.
func TestObserveGraphBoundsAgentStrings(t *testing.T) {
	g := entitygraph.New()
	h := &AgentHandler{graph: g}
	long := make([]byte, maxGraphStringLen+1)
	for i := range long {
		long[i] = 'a'
	}
	h.observeGraph("pc-1", model.Event{Details: `{"domain":"` + string(long) + `"}`, OccurredAt: time.Now()})
	h.observeGraph("pc-1", model.Event{Details: `{"remote_ip":"` + string(long) + `"}`, OccurredAt: time.Now()})
	if g.Size() != 0 {
		t.Fatalf("aşırı uzun dizgeler grafa girmemeli: %d", g.Size())
	}
	// Sınırdaki uzunluk kabul edilir.
	h.observeGraph("pc-1", model.Event{Details: `{"domain":"` + string(long[:maxGraphStringLen]) + `"}`, OccurredAt: time.Now()})
	if g.Size() != 1 {
		t.Fatalf("sınırdaki dizge kabul edilmeli: %d", g.Size())
	}

	// 10k derinlikli zincir: yalnız maxParentChain halka işlenir.
	chain := `"p0"`
	for i := 1; i < 10000; i++ {
		chain += `,"p` + itoa(i) + `"`
	}
	g2 := entitygraph.New()
	h2 := &AgentHandler{graph: g2, seqModel: aibrain.NewSeqModels()}
	h2.observeGraph("pc-1", model.Event{Details: `{"process":"leaf","parent_chain":[` + chain + `]}`, OccurredAt: time.Now()})
	if g2.Size() != maxParentChain {
		t.Fatalf("zincir derinlik tavanı %d olmalı: %d", maxParentChain, g2.Size())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Z5-18: sekans taban çizgisi KİRACI başınadır — A kiracısı olaylarıyla öğrenilen zincir
// B kiracısının skorunu etkilemez.
func TestObserveGraphSeqModelIsPerTenant(t *testing.T) {
	m := aibrain.NewSeqModels()
	h := &AgentHandler{seqModel: m}
	for i := 0; i < 5; i++ {
		h.observeGraph("pc-1", model.Event{
			TenantID:   "acme",
			Details:    `{"process":"ipconfig.exe","parent_chain":["cmd.exe","explorer.exe"]}`,
			OccurredAt: time.Now(),
		})
	}
	chain := []string{"explorer.exe", "cmd.exe", "ipconfig.exe"}
	if s := m.Score("acme", chain); s.Score > 20 {
		t.Fatalf("acme kendi taban çizgisinde sıradan görmeli: %v", s.Score)
	}
	if s := m.Score("globex", chain); s.Score < 80 {
		t.Fatalf("globex acme'nin taban çizgisinden etkilenmemeli: %v", s.Score)
	}
}

// S4 (kablolama): graf besleyicisi kenarları GÖNDEREN cihaza atfeder; bütçesi dolan cihazın
// (süreç soyağacı dahil) yeni kenarları düşer, başka cihazın kenarları etkilenmez.
func TestObserveGraphChargesDeviceBudget(t *testing.T) {
	g := entitygraph.New()
	g.SetLimits(entitygraph.Limits{MaxEdgesPerDevice: 5})
	h := &AgentHandler{graph: g}
	for i := 0; i < 50; i++ {
		h.observeGraph("bad", model.Event{Details: `{"domain":"junk` + strconv.Itoa(i) + `.evil"}`, OccurredAt: time.Now()})
		h.observeGraph("bad", model.Event{Details: `{"process":"p` + strconv.Itoa(i) + `.exe","parent_chain":["x` + strconv.Itoa(i) + `.exe"]}`, OccurredAt: time.Now()})
	}
	h.observeGraph("good", model.Event{Details: `{"domain":"fine.example"}`, OccurredAt: time.Now()})
	if st := g.Stats(); st.Edges != 5+1 || st.DeviceDropped != 95 || st.Evicted != 0 {
		t.Fatalf("bad cihazı bütçesini aşmamalı, good etkilenmemeli: %+v", st)
	}
	if got := g.Targets(entitygraph.Node{Kind: entitygraph.Device, ID: "good"}, entitygraph.Resolved); len(got) != 1 {
		t.Fatalf("good cihazın kenarı korunmalı: %+v", got)
	}
}
