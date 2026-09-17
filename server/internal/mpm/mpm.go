// Package mpm, ÇOK-DESENLİ EŞLEŞTİRME (multi-pattern matching) için saf-Go bir
// Aho-Corasick otomatı sağlar. Tek metin geçişinde, DESEN SAYISINDAN BAĞIMSIZ
// olarak (O(metin+eşleşme)) verilen tüm literal desenlerin hangilerinin metinde
// geçtiğini bulur. Bu, tespit motorunun (detect) yüzlerce/binlerce IOC/threat-intel
// literalini olay başına yeniden tarayarak O(kural×altdize)'ye düşmesini engeller —
// IDS motorlarının (ör. IDS MPM) ölçekleme deseninin uç-nokta telemetrisine
// uyarlanmış, özgün bir gerçeklemesidir.
//
// Eşleştirme küçük/büyük harf DUYARSIZDIR (desenler ve metin küçük harfe indirgenir),
// çünkü detect.Rule.Contains semantiği de duyarsızdır. Kurulduktan sonra Matcher
// salt-okunurdur ve eşzamanlı okunabilir (paylaşımlı durum değişmez).
//
// Bağımlılıksız (yalnız stdlib: strings).
package mpm

import "strings"

// node, otomatın tek bir durumudur (trie düğümü + Aho-Corasick fail/output eklentileri).
type node struct {
	children map[byte]int // geçiş: bayt → hedef düğüm indeksi
	fail     int          // başarısızlık bağlantısı (en uzun uygun son-ek düğümü)
	outputs  []int        // bu düğümde BİTEN desen indeksleri (fail-zinciri boyunca birleştirilmiş)
}

// Matcher, kurulmuş (fail-bağlantıları hesaplanmış) bir Aho-Corasick otomatıdır.
type Matcher struct {
	nodes []node // 0 = kök
	npat  int    // Build'e verilen desen sayısı (boş desenler dahil, indeks tutarlılığı için)
}

// Build, verilen desenlerden bir Matcher kurar. Dönen eşleştiricinin bildirdiği
// desen indeksleri, patterns dilimindeki indekslerle BİREBİR aynıdır (çağıran,
// indeksi kendi kural/kayıt tablosuna eşleyebilir). Boş desenler otomata eklenmez
// ama indeks sayımına dahildir (npat), böylece dış eşleme kaymaz.
func Build(patterns []string) *Matcher {
	m := &Matcher{npat: len(patterns)}
	m.nodes = []node{{children: map[byte]int{}}} // kök
	for pi, p := range patterns {
		p = strings.ToLower(p)
		if p == "" {
			continue // boş desen her metinde geçer sayılmaz; atlanır
		}
		cur := 0
		for i := 0; i < len(p); i++ {
			b := p[i]
			nxt, ok := m.nodes[cur].children[b]
			if !ok {
				nxt = len(m.nodes)
				m.nodes = append(m.nodes, node{children: map[byte]int{}})
				m.nodes[cur].children[b] = nxt
			}
			cur = nxt
		}
		m.nodes[cur].outputs = append(m.nodes[cur].outputs, pi)
	}
	m.buildFail()
	return m
}

// buildFail, başarısızlık bağlantılarını ve birleştirilmiş çıktı kümelerini genişlik-
// öncelikli (BFS) sırayla hesaplar. BFS, bir düğümün fail-hedefinin DAHA SIĞ (daha
// önce işlenmiş) olmasını garanti eder; böylece fail-hedefinin birleştirilmiş
// outputs'u hazırdır ve son-ek eşleşmeleri düğüme taşınabilir.
func (m *Matcher) buildFail() {
	queue := make([]int, 0, len(m.nodes))
	// Kökün doğrudan çocukları köke (0) başarısızlaşır.
	for _, c := range m.nodes[0].children {
		m.nodes[c].fail = 0
		queue = append(queue, c)
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for b, v := range m.nodes[u].children {
			queue = append(queue, v)
			// v'nin fail'i: u'nun fail-zincirinde b geçişi olan ilk düğümün çocuğu.
			f := m.nodes[u].fail
			for f != 0 {
				if _, ok := m.nodes[f].children[b]; ok {
					break
				}
				f = m.nodes[f].fail
			}
			if nf, ok := m.nodes[f].children[b]; ok && nf != v {
				m.nodes[v].fail = nf
			} else {
				m.nodes[v].fail = 0
			}
			// Son-ek eşleşmelerini taşı: v'de biten desenler + fail-hedefindekiler.
			m.nodes[v].outputs = append(m.nodes[v].outputs, m.nodes[m.nodes[v].fail].outputs...)
		}
	}
}

// collect, metni tek geçişte tarar ve geçen desenlerin indekslerini İLK-GÖRÜLME
// sırasında (yinelenmeden) döner. stopFirst=true ise ilk eşleşmede durur (MatchAny).
func (m *Matcher) collect(text string, stopFirst bool) []int {
	if len(m.nodes) <= 1 {
		return nil // hiç desen yok
	}
	text = strings.ToLower(text)
	var seen map[int]bool
	var out []int
	cur := 0
	for i := 0; i < len(text); i++ {
		b := text[i]
		// b için geçiş yoksa fail-zincirini izle (kökte dururuz).
		for cur != 0 {
			if _, ok := m.nodes[cur].children[b]; ok {
				break
			}
			cur = m.nodes[cur].fail
		}
		if nxt, ok := m.nodes[cur].children[b]; ok {
			cur = nxt
		}
		for _, pi := range m.nodes[cur].outputs {
			if seen == nil {
				seen = make(map[int]bool)
			}
			if seen[pi] {
				continue
			}
			seen[pi] = true
			out = append(out, pi)
			if stopFirst {
				return out
			}
		}
	}
	return out
}

// Matches, metinde geçen tüm desenlerin indekslerini (ilk-görülme sırasında,
// yinelenmeden) döner. Hiç eşleşme yoksa nil.
func (m *Matcher) Matches(text string) []int { return m.collect(text, false) }

// MatchAny, metinde EN AZ BİR desen geçiyorsa true döner (ilk eşleşmede durur).
func (m *Matcher) MatchAny(text string) bool { return len(m.collect(text, true)) > 0 }

// PatternCount, Build'e verilen desen sayısını (boşlar dahil) döner.
func (m *Matcher) PatternCount() int { return m.npat }
