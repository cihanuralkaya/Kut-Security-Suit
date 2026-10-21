package aisec

// service.go — AG-07: aisec analiz çekirdeğinin EŞZAMANLI-GÜVENLİ canlı sarmalayıcısı.
// Agent olaylarını (kimlik/read/write/delegation/influence) ingest eder, Agent Causality
// Graph'ı besler ve exfil bulgularını üretir. Bu, AG düzlemini gözlemlenebilir kılan
// "live-wire" seam'idir (telemetri kaynağı buraya bağlanır; SOC salt-okunur uçtan tüketir).
// AG düzlemi gözlem/öneri katmanıdır (INV-AG-010): YÜRÜTMEZ, yalnız DATA üretir.
//
// ÇOK-KİRACILI BÖLÜMLEME (Z5-02 / Z4a-05): Service artık TEK küresel graf değil, kiracı
// BAŞINA bir CausalityGraph tutar. Her gözlem/okuma açıkça bir kiracı bölümü alır; bölüm
// anahtarı SUNUCU-TARAFI çözülmüş kiracıdır (istemciden asla). Böylece bir kiracı başka
// kiracının düğüm güvenini ÜZERİNE YAZAMAZ, düğüm/kenar tavanını doldurup başkasının
// düğümlerini tahliye edemez (tavan bölüm başınadır) ve başkasının bulgusunu OKUYAMAZ.
// "" bölümü PLATFORM bölümüdür (kiracısız/tek-kiracılı dağıtım ve platform admini yazımları).

import (
	"errors"
	"sort"
	"sync"
)

// Sınırlar: kimlik uzunluğu ve bölüm sayısı. Düğüm/kenar tavanları bölüm başına
// CausalityGraph'ta (defaultMaxNodes/defaultMaxEdges) uygulanır.
const (
	// MaxIDLen, düğüm kimliği azami uzunluğudur (bayt). Aşan gözlem reddedilir.
	MaxIDLen = 256
	// maxPartitions, eşzamanlı kiracı bölümü üst sınırıdır (bellek DoS savunması).
	maxPartitions = 1024
)

var (
	// ErrIDTooLong, düğüm kimliği MaxIDLen'i aştığında döner.
	ErrIDTooLong = errors.New("aisec: düğüm kimliği çok uzun")
	// ErrTooManyTenants, yeni bir kiracı bölümü açma sınırı aşıldığında döner (fail-closed).
	ErrTooManyTenants = errors.New("aisec: kiracı bölümü sınırı aşıldı")
)

// Service, kiracı-bölümlü causality graph'larını eşzamanlı erişime karşı sarar.
// CausalityGraph tek-thread varsaydığından tüm erişim burada tek kilit altındadır.
type Service struct {
	mu    sync.Mutex
	parts map[string]*CausalityGraph
}

// NewService oluşturur.
func NewService() *Service { return &Service{parts: map[string]*CausalityGraph{}} }

// TenantFinding, bir exfil bulgusunu ait olduğu kiracı bölümüyle birlikte taşır.
type TenantFinding struct {
	Tenant string
	ExfilFinding
}

// part, kiracı bölümünü döner (yoksa oluşturur). Kilit altında çağrılmalıdır.
func (s *Service) part(tenant string) (*CausalityGraph, error) {
	if g, ok := s.parts[tenant]; ok {
		return g, nil
	}
	if len(s.parts) >= maxPartitions {
		return nil, ErrTooManyTenants
	}
	g := NewCausalityGraph()
	s.parts[tenant] = g
	return g, nil
}

// withPart, kilit altında bölümü bulup fn'i çalıştırır; kimlik uzunluğu ve bölüm
// sınırı burada uygulanır.
func (s *Service) withPart(tenant string, fn func(g *CausalityGraph), ids ...string) error {
	for _, id := range ids {
		if len(id) > MaxIDLen {
			return ErrIDTooLong
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.part(tenant)
	if err != nil {
		return err
	}
	fn(g)
	return nil
}

// ObserveNode, kiracı bölümüne bir düğüm gözlemi kaydeder (agent/tool/memory/context/
// credential/external).
func (s *Service) ObserveNode(tenant, id string, kind NodeKind, trust TrustLevel) error {
	return s.withPart(tenant, func(g *CausalityGraph) { g.AddNode(id, kind, trust) }, id)
}

// ObserveRead, "agent, source'u okudu" gözlemi (taint source → agent).
func (s *Service) ObserveRead(tenant, agent, source string) error {
	return s.withPart(tenant, func(g *CausalityGraph) { g.AddRead(agent, source) }, agent, source)
}

// ObserveWrite, "agent, sink'e yazdı" gözlemi (egress).
func (s *Service) ObserveWrite(tenant, agent, sink string) error {
	return s.withPart(tenant, func(g *CausalityGraph) { g.AddWrite(agent, sink) }, agent, sink)
}

// ObserveDelegate, "delegator → delegatee" delegation gözlemi.
func (s *Service) ObserveDelegate(tenant, from, to string) error {
	return s.withPart(tenant, func(g *CausalityGraph) { g.AddDelegate(from, to) }, from, to)
}

// ObserveInfluence, "from → to" etki gözlemi.
func (s *Service) ObserveInfluence(tenant, from, to string) error {
	return s.withPart(tenant, func(g *CausalityGraph) { g.AddInfluence(from, to) }, from, to)
}

// Findings, YALNIZ verilen kiracı bölümünün o anki exfil bulgularının anlık kopyasını döner
// (eşzamanlı-güvenli). Bölüm yoksa nil. Bulgular DATA'dır; SOC/analist tüketir, enforcement
// §0 zincirinden geçer (INV-AG-010).
func (s *Service) Findings(tenant string) []ExfilFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.parts[tenant]
	if !ok {
		return nil
	}
	return g.DetectExfiltration()
}

// FindingsAll, TÜM kiracı bölümlerinin bulgularını bölüm etiketiyle döner — YALNIZ platform
// admini yolu içindir (kiracıya bağlı çağıranlar Findings(tenant) kullanmalıdır). Sıra
// kararlıdır (kiracıya, sonra agent'a göre).
func (s *Service) FindingsAll() []TenantFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenants := make([]string, 0, len(s.parts))
	for t := range s.parts {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	var out []TenantFinding
	for _, t := range tenants {
		fs := s.parts[t].DetectExfiltration()
		sort.Slice(fs, func(i, j int) bool { return fs[i].AgentID < fs[j].AgentID })
		for _, f := range fs {
			out = append(out, TenantFinding{Tenant: t, ExfilFinding: f})
		}
	}
	return out
}
