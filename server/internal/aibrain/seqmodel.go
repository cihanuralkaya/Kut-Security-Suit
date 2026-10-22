package aibrain

// seqmodel.go — süreç-zinciri sekans nadirlik modeli. SINIRLI ve KİRACI-BÖLÜMLÜ:
// girdi cihaz-kontrollü süreç adlarından gelir; önceki sürüm sınırsız büyür (OOM) ve tüm
// kiracıların taban çizgisini tek modelde karıştırırdı (bir kiracının kendi zincirini "normal"
// diye zehirlemesi başkalarının skorunu da etkilerdi). Şimdi: kaynak token başına LRU tahliyesi,
// token başına hedef tavanı, token/dizi uzunluğu tavanı, TTL süpürmesi ve kiracı başına model.

import (
	"container/list"
	"sort"
	"sync"
	"time"
)

// SeqLimits, bir sekans modelinin SERT tavanlarıdır; sıfır alan varsayılana döner.
type SeqLimits struct {
	MaxSources int // kaynak token sayısı (aşılınca en az-yakın kullanılan LRU tahliye)
	MaxTargets int // kaynak token başına hedef sayısı (dolunca yeni hedef ÖĞRENİLMEZ)
	MaxTokens  int // tek diziden işlenen azami token sayısı
	MaxTokenLn int // token azami uzunluğu (bayt); aşan geçiş öğrenilmez
}

// DefaultSeqLimits, üretim varsayılanlarıdır.
func DefaultSeqLimits() SeqLimits {
	return SeqLimits{MaxSources: 20_000, MaxTargets: 64, MaxTokens: 64, MaxTokenLn: 256}
}

func (l SeqLimits) normalized() SeqLimits {
	d := DefaultSeqLimits()
	if l.MaxSources <= 0 {
		l.MaxSources = d.MaxSources
	}
	if l.MaxTargets <= 0 {
		l.MaxTargets = d.MaxTargets
	}
	if l.MaxTokens <= 0 {
		l.MaxTokens = d.MaxTokens
	}
	if l.MaxTokenLn <= 0 {
		l.MaxTokenLn = d.MaxTokenLn
	}
	return l
}

// SeqStats, modelin anlık boyutu ve kümülatif sayaçlarıdır.
type SeqStats struct {
	Sources int
	Dropped int64 // tavan/uzunluk nedeniyle öğrenilmeyen geçişler
	Evicted int64 // LRU ile atılan kaynak tokenlar
	Pruned  int64 // TTL ile atılan kaynak tokenlar
}

type seqSrc struct {
	targets map[string]int
	total   int
	last    time.Time
	elem    *list.Element
}

// SeqModel, deterministik bir n-gram (bigram/Markov) nadirlik modelidir. Gözlenen
// dizilerden ardışık token geçişlerinin sıklığını öğrenir; yeni bir diziyi bu taban
// çizgisine göre puanlar. Nadir/görülmemiş geçişler yüksek anomali skoru üretir —
// çıktı açıklanabilirdir (hangi geçişin nadir olduğu bildirilir). Eşzamanlı güvenli, sınırlı.
type SeqModel struct {
	mu      sync.RWMutex
	trans   map[string]*seqSrc
	lru     *list.List // ön = en son kullanılan kaynak
	lim     SeqLimits
	now     func() time.Time
	dropped int64
	evicted int64
	pruned  int64
}

// NewSeqModel, boş bir sekans modeli oluşturur (varsayılan tavanlarla).
func NewSeqModel() *SeqModel {
	return &SeqModel{trans: map[string]*seqSrc{}, lru: list.New(), lim: DefaultSeqLimits(), now: time.Now}
}

// SetLimits, tavanları ayarlar (başlangıçta). Sıfır alan varsayılana döner.
func (m *SeqModel) SetLimits(l SeqLimits) {
	m.mu.Lock()
	m.lim = l.normalized()
	m.mu.Unlock()
}

// Stats, anlık boyut ve sayaçları döner.
func (m *SeqModel) Stats() SeqStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return SeqStats{Sources: len(m.trans), Dropped: m.dropped, Evicted: m.evicted, Pruned: m.pruned}
}

// Observe, bir diziyi taban çizgisine ekler (bigram sayaçlarını artırır). Normal
// davranış ne kadar çok gözlenirse o kadar "sıradan" sayılır. Dizi MaxTokens'a kırpılır;
// aşırı uzun token içeren geçişler ve dolu kaynağa yeni hedefler öğrenilmez (sayılır).
func (m *SeqModel) Observe(tokens []string) {
	if len(tokens) < 2 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(tokens) > m.lim.MaxTokens {
		m.dropped += int64(len(tokens) - m.lim.MaxTokens)
		tokens = tokens[len(tokens)-m.lim.MaxTokens:] // yaprağa en yakın kısım
	}
	now := m.now()
	for i := 0; i+1 < len(tokens); i++ {
		a, b := tokens[i], tokens[i+1]
		if len(a) > m.lim.MaxTokenLn || len(b) > m.lim.MaxTokenLn {
			m.dropped++
			continue
		}
		src := m.trans[a]
		if src == nil {
			for len(m.trans) >= m.lim.MaxSources {
				back := m.lru.Back()
				if back == nil {
					break
				}
				m.drop(back.Value.(string))
				m.evicted++
			}
			src = &seqSrc{targets: map[string]int{}}
			src.elem = m.lru.PushFront(a)
			m.trans[a] = src
		} else {
			m.lru.MoveToFront(src.elem)
		}
		if _, known := src.targets[b]; !known && len(src.targets) >= m.lim.MaxTargets {
			m.dropped++
			src.last = now
			continue
		}
		src.targets[b]++
		src.total++
		src.last = now
	}
}

// drop, bir kaynak token'ı kaldırır. Kilit altında.
func (m *SeqModel) drop(a string) {
	if src := m.trans[a]; src != nil {
		m.lru.Remove(src.elem)
		delete(m.trans, a)
	}
}

// Prune, sunucu-saatiyle son kullanımı before'dan eski kaynak tokenları kaldırır (TTL süpürmesi).
func (m *SeqModel) Prune(before time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	var victims []string
	for a, src := range m.trans {
		if src.last.Before(before) {
			victims = append(victims, a)
		}
	}
	for _, a := range victims {
		m.drop(a)
	}
	m.pruned += int64(len(victims))
	return len(victims)
}

// rarity, bir dizinin 0..100 nadirlik skorunu ve en nadir geçişin açıklamasını döner.
// Her geçişin nadirliği: görülmemiş (kaynak hiç gözlenmemiş VEYA bu hedefe hiç
// gidilmemiş) → 1.0; aksi halde 1 - P(hedef|kaynak). Skor, geçiş nadirliklerinin
// ortalamasıdır. 2'den kısa diziler için 0 (kıyaslanacak geçiş yok).
func (m *SeqModel) rarity(tokens []string) (float64, string) {
	if len(tokens) < 2 {
		return 0, ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var sum float64
	var n int
	worst := -1.0
	worstDesc := ""
	for i := 0; i+1 < len(tokens); i++ {
		a, b := tokens[i], tokens[i+1]
		var r float64
		src := m.trans[a]
		if src == nil || src.total == 0 || src.targets[b] == 0 {
			r = 1.0 // görülmemiş geçiş → azami nadirlik
		} else {
			r = 1.0 - float64(src.targets[b])/float64(src.total)
		}
		sum += r
		n++
		if r > worst {
			worst = r
			worstDesc = a + "→" + b
		}
	}
	if n == 0 {
		return 0, ""
	}
	return (sum / float64(n)) * 100, worstDesc
}

// Score, bir dizinin nadirlik skorunu açıklamalı SequenceScore olarak döner
// (salt-okunur sorgu — taban çizgisini DEĞİŞTİRMEZ). Analist tehdit-avında bir
// süreç zincirini ortama göre puanlamak için kullanır.
func (m *SeqModel) Score(tokens []string) SequenceScore {
	score, worst := m.rarity(tokens)
	rationale := "tüm geçişler taban çizgisinde sık"
	if worst != "" && score > 0 {
		rationale = "en nadir geçiş: " + worst
	}
	return SequenceScore{Score: score, Rationale: rationale, Source: "local"}
}

// maxSeqTenants, eşzamanlı kiracı modeli üst sınırıdır (bellek DoS savunması).
const maxSeqTenants = 4096

// SeqModels, KİRACI BAŞINA bir SeqModel tutar: bir kiracının taban çizgisi başkasının
// skorunu etkilemez ve bir kiracının tavanı yalnız kendi modelini doldurur. Kiracı anahtarı
// SUNUCU-TARAFI çözülmüş kiracıdır (cihaz/olay kiracısı ya da çağıranın kiracısı).
type SeqModels struct {
	mu      sync.Mutex
	models  map[string]*SeqModel
	lim     SeqLimits
	dropped int64 // kiracı sınırı yüzünden reddedilen Observe
}

// NewSeqModels, boş bir kiracı-bölümlü sekans modeli kaydı oluşturur.
func NewSeqModels() *SeqModels {
	return &SeqModels{models: map[string]*SeqModel{}, lim: DefaultSeqLimits()}
}

// NewSeqModelsWith, mevcut tek bir modeli verilen kiracı bölümü olarak benimseyen kayıt döner
// (geriye uyumluluk: tek-bölümlü kullanım).
func NewSeqModelsWith(tenant string, m *SeqModel) *SeqModels {
	r := NewSeqModels()
	if m != nil {
		r.models[tenant] = m
	}
	return r
}

// SetLimits, yeni oluşturulacak kiracı modelleri için tavanları ayarlar (başlangıçta).
func (r *SeqModels) SetLimits(l SeqLimits) {
	r.mu.Lock()
	r.lim = l.normalized()
	for _, m := range r.models {
		m.SetLimits(l)
	}
	r.mu.Unlock()
}

// Observe, diziyi YALNIZ verilen kiracının modeline öğretir. Kiracı sınırı aşılırsa öğrenilmez.
func (r *SeqModels) Observe(tenant string, tokens []string) {
	r.mu.Lock()
	m := r.models[tenant]
	if m == nil {
		if len(r.models) >= maxSeqTenants {
			r.dropped++
			r.mu.Unlock()
			return
		}
		m = NewSeqModel()
		m.lim = r.lim
		r.models[tenant] = m
	}
	r.mu.Unlock()
	m.Observe(tokens)
}

// Score, diziyi YALNIZ verilen kiracının taban çizgisine göre puanlar (salt-okunur). Kiracının
// modeli yoksa boş taban çizgisi (her geçiş görülmemiş) kullanılır — başka kiracının verisine
// ASLA düşülmez.
func (r *SeqModels) Score(tenant string, tokens []string) SequenceScore {
	r.mu.Lock()
	m := r.models[tenant]
	r.mu.Unlock()
	if m == nil {
		m = NewSeqModel()
	}
	return m.Score(tokens)
}

// Prune, tüm kiracı modellerinde TTL süpürmesi yapar; atılan toplam kaynak sayısını döner.
func (r *SeqModels) Prune(before time.Time) int {
	r.mu.Lock()
	models := make([]*SeqModel, 0, len(r.models))
	for _, m := range r.models {
		models = append(models, m)
	}
	r.mu.Unlock()
	n := 0
	for _, m := range models {
		n += m.Prune(before)
	}
	return n
}

// Stats, tüm kiracı modellerinin toplam boyut/sayaçlarını döner.
func (r *SeqModels) Stats() SeqStats {
	r.mu.Lock()
	models := make([]*SeqModel, 0, len(r.models))
	for _, m := range r.models {
		models = append(models, m)
	}
	dropped := r.dropped
	r.mu.Unlock()
	var s SeqStats
	s.Dropped = dropped
	for _, m := range models {
		ms := m.Stats()
		s.Sources += ms.Sources
		s.Dropped += ms.Dropped
		s.Evicted += ms.Evicted
		s.Pruned += ms.Pruned
	}
	return s
}

// Tenants, modeli olan kiracıları sıralı döner (tanılama/test).
func (r *SeqModels) Tenants() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.models))
	for t := range r.models {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
