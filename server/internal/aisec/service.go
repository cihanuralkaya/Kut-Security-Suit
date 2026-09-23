package aisec

// service.go — AG-07: aisec analiz çekirdeğinin EŞZAMANLI-GÜVENLİ canlı sarmalayıcısı.
// Agent olaylarını (kimlik/read/write/delegation/influence) ingest eder, Agent Causality
// Graph'ı besler ve exfil bulgularını üretir. Bu, AG düzlemini gözlemlenebilir kılan
// "live-wire" seam'idir (telemetri kaynağı buraya bağlanır; SOC salt-okunur uçtan tüketir).
// AG düzlemi gözlem/öneri katmanıdır (INV-AG-010): YÜRÜTMEZ, yalnız DATA üretir.

import "sync"

// Service, causality graph'ı eşzamanlı erişime karşı sarar. CausalityGraph tek-thread
// varsaydığından tüm erişim burada tek kilit altındadır.
type Service struct {
	mu sync.Mutex
	g  *CausalityGraph
}

// NewService oluşturur.
func NewService() *Service { return &Service{g: NewCausalityGraph()} }

// ObserveNode, bir düğüm gözlemi kaydeder (agent/tool/memory/context/credential/external).
func (s *Service) ObserveNode(id string, kind NodeKind, trust TrustLevel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.g.AddNode(id, kind, trust)
}

// ObserveRead, "agent, source'u okudu" gözlemi (taint source → agent).
func (s *Service) ObserveRead(agent, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.g.AddRead(agent, source)
}

// ObserveWrite, "agent, sink'e yazdı" gözlemi (egress).
func (s *Service) ObserveWrite(agent, sink string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.g.AddWrite(agent, sink)
}

// ObserveDelegate, "delegator → delegatee" delegation gözlemi.
func (s *Service) ObserveDelegate(from, to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.g.AddDelegate(from, to)
}

// ObserveInfluence, "from → to" etki gözlemi.
func (s *Service) ObserveInfluence(from, to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.g.AddInfluence(from, to)
}

// Findings, o anki exfil bulgularının anlık kopyasını döner (eşzamanlı-güvenli). Bulgular
// DATA'dır; SOC/analist tüketir, enforcement §0 zincirinden geçer (INV-AG-010).
func (s *Service) Findings() []ExfilFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.g.DetectExfiltration()
}
