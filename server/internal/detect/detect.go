// Package detect, sunucu-taraflı tespit kural motorudur (YAML-benzeri, hafif).
// Ajanın ürettiği ham olayları merkezi, ADLANDIRILMIŞ tespit kurallarına eşler:
// her kural bir kategori/mesaj örüntüsüne bakar, normalize edilmiş bir önem düzeyi
// ve MITRE ATT&CK tekniği atar. Böylece tespit içeriği ajan yeniden dağıtılmadan
// merkezden yönetilir ve SOC "hangi tespitlerin devrede olduğunu" görebilir.
//
// Bağımlılıksız (yalnız stdlib + mitre + model).
package detect

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"kut.corp/suite/server/internal/mitre"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/mpm"
)

// Rule, bir tespit kuralıdır. Tüm belirtilen koşullar AND'lenir:
//   - Category boşsa her kategori eşleşir.
//   - Contains: TÜM parçalar (küçük/büyük harf duyarsız) mesajda geçmeli.
//   - MessageRegex (v2): mesaj bu regex'e uymalı (küçük/büyük harf duyarsız).
//   - Fields (v2): olayın Details JSON'unda her alan, belirtilen alt-dizeyi
//     (küçük/büyük harf duyarsız) içermeli — ör. {"disk_encryption":"off"}.
//   - MinSeverity (v2): olayın önem düzeyi en az bu olmalı (INFO<..<CRITICAL).
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category,omitempty"`
	Contains []string `json:"contains,omitempty"`
	// Absent (v3): NEGATİF içerik (IDS `content:!"..."` muadili). Mesaj bu
	// literallerden HERHANGİ BİRİNİ içeriyorsa kural eşleşmez — dışlama/istisna ile
	// yanlış-pozitif azaltma (ör. Contains:["powershell"] + Absent:["-signed"]).
	// Küçük/büyük harf duyarsız. Yalnız-negatif kural ön-filtrelenemez (alwaysEval).
	Absent       []string          `json:"absent,omitempty"`
	MessageRegex string            `json:"message_regex,omitempty"`
	Fields       map[string]string `json:"fields,omitempty"`
	MinSeverity  string            `json:"min_severity,omitempty"`
	// Sequence (v3): SIRALI içerik eşleşmesi (IDS `content`+`distance`/`within`
	// muadili). Contains sırasız AND iken, Sequence literalleri mesajda VERİLEN
	// SIRAYLA (her biri öncekinin bitişinden sonra) geçmelidir — komut yapısı gibi
	// örüntüler için (ör. "powershell" → "downloadstring" → "invoke"). Küçük/büyük
	// harf duyarsız.
	Sequence []string `json:"sequence,omitempty"`
	// WithinBytes (v3): >0 ise, ardışık Sequence eşleşmeleri arasındaki boşluk
	// (önceki eşleşmenin bitişi ile sonrakinin başlangıcı arası bayt) EN FAZLA bu
	// kadar olabilir (yakınlık kısıtı). 0 → boşluk sınırsız (yalnız sıra önemli).
	WithinBytes int             `json:"within_bytes,omitempty"`
	Severity    string          `json:"severity"` // kuralın atadığı normalize önem düzeyi
	Technique   mitre.Technique `json:"technique"`
	// Detection-as-Code yaşam-döngüsü + köken meta verisi (opsiyonel):
	Status     string   `json:"status,omitempty"`     // draft | active | retired ("" = active)
	Author     string   `json:"author,omitempty"`     // kuralı yazan
	Version    string   `json:"version,omitempty"`    // kural sürümü (ör. "1.2.0")
	References []string `json:"references,omitempty"` // kaynak/analiz bağlantıları
	// Threshold (opsiyonel): tekrar-eşiği. Ayarlıysa bu kuralın tespiti, bir zaman
	// penceresinde EN AZ Count kez görülmeden alarma DÖNÜŞMEZ (brute-force/tarama).
	// Eşik durumu STATEFUL'dir ve motorun DIŞINDA (threshold.Gate) tutulur — motor
	// atomik hot-reload ile değişse de sayaç korunur. Nil → eşik yok (varsayılan).
	Threshold *ThresholdSpec `json:"threshold,omitempty"`
	// Bits (opsiyonel): çok-aşamalı tespit durum bitleri (IDS flowbits/xbits
	// muadili). Require: hepsi kuruluyken alarma izin verilir (ön-koşul). Set: kural
	// eşleşip ön-koşulu geçince kurulur. Durum STATEFUL'dir ve motor DIŞINDA
	// (detbits.Store) tutulur. Nil → bit mantığı yok (varsayılan).
	Bits *BitSpec `json:"bits,omitempty"`
}

// BitSpec, bir kuralın çok-aşamalı tespit bitleri yapılandırmasıdır. Require:
// alarm için host'ta kurulu olması gereken bitler. Set: eşleşince host'ta kurulacak
// bitler. TTLSeconds: Set bitlerinin ömrü (0 → 3600). Track: bit kapsamı —
// "device" (varsayılan), "tenant", "global".
type BitSpec struct {
	Require    []string `json:"require,omitempty"`
	RequireNot []string `json:"require_not,omitempty"` // host'ta kurulu OLMAMASI gereken bitler (IDS flowbits:isnotset)
	Set        []string `json:"set,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	Track      string   `json:"track,omitempty"`
}

// ThresholdSpec, bir kuralın tekrar-eşiği yapılandırmasıdır (IDS `threshold`
// muadili). Count: pencerede alarm için gereken en az tespit sayısı. Seconds:
// pencere süresi (saniye). Track: sayacın kapsamı — "device" (varsayılan; cihaz
// başına), "tenant" (kiracı başına), "global" (tümü tek sayaç).
type ThresholdSpec struct {
	Count   int    `json:"count"`
	Seconds int    `json:"seconds"`
	Track   string `json:"track,omitempty"`
}

// Active, kuralın değerlendirmeye dahil olup olmadığını döner. Boş ya da "active"
// → etkin; "draft"/"retired" → yalnız katalogda görünür, olay-alımında değerlendirilmez.
func (r Rule) Active() bool {
	s := strings.ToLower(strings.TrimSpace(r.Status))
	return s == "" || s == "active"
}

// Detection, eşleşen bir kuralın ürettiği tespittir.
type Detection struct {
	RuleID    string          `json:"rule_id"`
	RuleName  string          `json:"rule_name"`
	Severity  string          `json:"severity"`
	Technique mitre.Technique `json:"technique"`
	// Threshold, kuralın tekrar-eşiği (varsa) — alarm katmanı, tespiti alarma
	// dönüştürmeden önce eşik kapısını (threshold.Gate) bununla uygular. Nil → eşik yok.
	Threshold *ThresholdSpec `json:"threshold,omitempty"`
	// Bits, kuralın çok-aşamalı tespit bitleri (varsa) — alarm katmanı, ön-koşul
	// (Require) ve durum-kurma (Set) için detbits.Store'u bununla kullanır. Nil → yok.
	Bits *BitSpec `json:"bits,omitempty"`
}

// sevRank, önem düzeylerini sıralar (eşik karşılaştırması için).
var sevRank = map[string]int{"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

// compiledRule, bir kuralı ön-derlenmiş regex'iyle birlikte tutar.
type compiledRule struct {
	rule Rule
	re   *regexp.Regexp // MessageRegex derlenmiş; yoksa nil
}

// matches, derlenmiş kuralın verilen olaya uyup uymadığını söyler.
func (c compiledRule) matches(ev model.Event) bool {
	r := c.rule
	if r.Category != "" && r.Category != ev.Category {
		return false
	}
	if r.MinSeverity != "" && sevRank[ev.Severity] < sevRank[r.MinSeverity] {
		return false
	}
	msg := strings.ToLower(ev.Message)
	for _, sub := range r.Contains {
		if !strings.Contains(msg, strings.ToLower(sub)) {
			return false
		}
	}
	for _, sub := range r.Absent {
		if sub != "" && strings.Contains(msg, strings.ToLower(sub)) {
			return false // dışlama literali mevcut → eşleşme iptal
		}
	}
	if c.re != nil && !c.re.MatchString(ev.Message) {
		return false
	}
	if len(r.Sequence) > 0 && !matchSequence(msg, r.Sequence, r.WithinBytes) {
		return false
	}
	if len(r.Fields) > 0 {
		var d map[string]any
		if ev.Details == "" || json.Unmarshal([]byte(ev.Details), &d) != nil {
			return false
		}
		for k, want := range r.Fields {
			v, ok := d[k]
			if !ok {
				return false
			}
			if !strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), strings.ToLower(want)) {
				return false
			}
		}
	}
	return true
}

// matchSequence, lowercase msg içinde seq literallerinin VERİLEN SIRAYLA geçip
// geçmediğini söyler: her literal öncekinin bitişinden SONRA gelmelidir. within>0
// ise ardışık eşleşmeler arasındaki boşluk (önceki-bitiş → sonraki-başlangıç) en
// fazla within bayt olmalıdır. Boş literaller atlanır. msg'in küçük harfe indirgenmiş
// olması beklenir; literaller burada indirgenir.
//
// within>0'da greedy en-erken arama YETERSİZDİR: önceki literalin daha GEÇ bir
// oluşumu, sonraki literali yakınlık penceresine sokabilir (ör. seq ["ab","xy"],
// within=1, "abzzzzzabxy" → ab@7,xy@9 geçerli). Bu yüzden dinamik programlama
// kullanılır: her literal için, önceki literalin ULAŞILABİLİR tüm bitiş konumlarından
// (prevEnds) sıra+yakınlıkla erişilen oluşumların bitişleri toplanır. prevEnds ARTAN
// tutulur; within için kayan-pencere alt-indeksiyle taranır → toplam O(k·M) (DoS-güvenli).
func matchSequence(msg string, seq []string, within int) bool {
	var prevEnds []int // önceki literalin ulaşılabilir bitiş konumları (ARTAN)
	first := true
	for _, s := range seq {
		if s == "" {
			continue
		}
		ls := strings.ToLower(s)
		var ends []int
		lp := 0 // within kayan-pencere alt indeksi (prevEnds içinde)
		for from := 0; ; {
			idx := strings.Index(msg[from:], ls)
			if idx < 0 {
				break
			}
			start := from + idx
			var reachable bool
			switch {
			case first:
				reachable = true
			case within <= 0:
				// yalnız sıra: en küçük önceki-bitiş start'tan önce geliyorsa yeter.
				reachable = len(prevEnds) > 0 && prevEnds[0] <= start
			default:
				// yakınlık: [start-within, start] penceresinde bir önceki-bitiş var mı?
				lo := start - within
				for lp < len(prevEnds) && prevEnds[lp] < lo {
					lp++ // start artan → lo artan; bu bitişler bir daha gerekmez.
				}
				reachable = lp < len(prevEnds) && prevEnds[lp] <= start
			}
			if reachable {
				ends = append(ends, start+len(ls)) // start artan → ends artan
			}
			from = start + 1
		}
		if len(ends) == 0 {
			return false
		}
		if within <= 0 {
			ends = ends[:1] // sıra-kısıtı için yalnız en erken bitiş yeterli (bellek sınırlama)
		}
		prevEnds = ends
		first = false
	}
	return true
}

// Engine, sıralı bir kural listesini değerlendirir. İKİ-AŞAMALI tespit yapar:
// (1) MPM ön-filtresi (Aho-Corasick) olay mesajını tek geçişte tarayıp yalnız
// ankrajı geçen kuralları aday seçer; (2) aday kurallar tam matches() ile doğrulanır.
// Böylece kural sayısı yüzlere/binlere çıksa da olay-başına maliyet, mesajı bir kez
// taramaya + yalnız aday kuralları doğrulamaya iner (IDS MPM deseninin uç-nokta
// uyarlaması). Ön-filtre SOUND'dur: yalnız "ankraj yoksa kesinlikle eşleşemez"
// kurallar elenir; ankrajı olmayan kurallar her olayda değerlendirilir.
type Engine struct {
	rules      []compiledRule
	prefilter  *mpm.Matcher // ankraj literalleri üzerinde çok-desenli ön-filtre
	patRule    []int        // ön-filtre desen indeksi → rules indeksi
	alwaysEval []int        // ankrajı olmayan (ön-filtrelenemez) kural indeksleri
}

// NewEngine, verilen kurallarla motor kurar. Kural verilmezse yerleşik varsayılan
// kural seti kullanılır. Geçersiz MessageRegex taşıyan kural, regex koşulu
// olmadan yüklenir (savunmacı; operatör kuralları LoadRules'ta önceden doğrulanır).
func NewEngine(rules []Rule) *Engine {
	if len(rules) == 0 {
		rules = DefaultRules()
	}
	cr := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		c := compiledRule{rule: r}
		if r.MessageRegex != "" {
			if re, err := regexp.Compile("(?i)" + r.MessageRegex); err == nil {
				c.re = re
			}
		}
		cr = append(cr, c)
	}
	e := &Engine{rules: cr}
	e.buildPrefilter()
	return e
}

// selectAnchor, bir kuralın Contains literalleri arasından ÖN-FİLTRE ANKRAJINI
// (IDS fast_pattern muadili) seçer. Dönen literal, kuralın MPM ön-filtresine
// koyulacak TEK anahtardır; boş dönerse kural her olayda tam değerlendirilir
// (güvenli geri düşüş). Seçilen ankraj, kuralın Contains kümesinden BİRİ OLMALIDIR:
// Contains koşulları AND'lendiği için, kümedeki herhangi bir literal metinde yoksa
// kural zaten eşleşemez — dolayısıyla o literali ankraj yapmak SOUND (yanlış-negatif
// üretmez). Kümede olmayan bir literal seçmek soundness'ı bozardı.
func selectAnchor(contains []string) string {
	// En UZUN literal en seçici ankrajdır (uzun dizeler olay akışında daha seyrek
	// görülür → ön-filtre daha çok kuralı eler). Trim'lenmiş literal orijinalin
	// alt-dizesi olduğundan, orijinal her göründüğünde ankraj da görünür: aday-küme
	// daima gerçek-kümenin üst-kümesidir (soundness korunur). Tümü boş/whitespace
	// ise "" döner ve kural alwaysEval'e düşer.
	best := ""
	for _, s := range contains {
		if s = strings.TrimSpace(s); len(s) > len(best) {
			best = s
		}
	}
	return best
}

// buildPrefilter, iki-aşamalı tespitin ön-filtresini (MPM) kurar. Her kuralın
// ankrajını selectAnchor ile seçip tüm ankrajları tek bir Aho-Corasick otomatına
// yükler; ankrajı olmayan kuralları alwaysEval'e alır. Ankraj→kural eşlemesi
// patRule ile tutulur. Ön-filtre boş olsa bile (tüm kurallar alwaysEval) motor
// doğru çalışır — yalnız doğrusal taramaya iner.
func (e *Engine) buildPrefilter() {
	e.patRule = e.patRule[:0]
	e.alwaysEval = e.alwaysEval[:0]
	var anchors []string
	for i, c := range e.rules {
		// Ankraj adayları: Contains ∪ Sequence. Her ikisinin de TÜM literalleri
		// eşleşme için gerekli olduğundan, herhangi biri sağlam (sound) ankrajdır.
		cands := c.rule.Contains
		if len(c.rule.Sequence) > 0 {
			cands = append(append([]string{}, c.rule.Contains...), c.rule.Sequence...)
		}
		a := strings.ToLower(strings.TrimSpace(selectAnchor(cands)))
		if a == "" {
			e.alwaysEval = append(e.alwaysEval, i)
			continue
		}
		anchors = append(anchors, a)
		e.patRule = append(e.patRule, i)
	}
	e.prefilter = mpm.Build(anchors)
}

// Evaluate, olaya uyan tüm tespitleri (sıralı) döner. Eşleşme yoksa nil. YALNIZ
// etkin (active) kurallar değerlendirilir; draft/retired kurallar atlanır (yaşam-
// döngüsü — katalogda görünür ama üretimde tetiklenmez).
func (e *Engine) Evaluate(ev model.Event) []Detection {
	// 1. aşama — ön-filtre: ankrajı olmayan kurallar daima aday; ankrajı mesajda
	// geçen kurallar adaya eklenir. cand[i], e.rules[i] için "tam doğrula" bayrağı.
	cand := make([]bool, len(e.rules))
	for _, ri := range e.alwaysEval {
		cand[ri] = true
	}
	if e.prefilter != nil {
		for _, pi := range e.prefilter.Matches(ev.Message) {
			cand[e.patRule[pi]] = true
		}
	}
	// 2. aşama — doğrulama: aday + etkin kurallar tam matches() ile sınanır. Kural
	// SIRASI korunur (aday olmayanlar atlanır), böylece çıktı doğrusal taramayla aynı.
	var out []Detection
	for i, c := range e.rules {
		if !cand[i] || !c.rule.Active() {
			continue
		}
		if c.matches(ev) {
			r := c.rule
			out = append(out, Detection{RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Technique: r.Technique, Threshold: r.Threshold, Bits: r.Bits})
		}
	}
	return out
}

// Rules, motorun kurallarını (katalog/görünürlük için) döner.
func (e *Engine) Rules() []Rule {
	cp := make([]Rule, len(e.rules))
	for i, c := range e.rules {
		cp[i] = c.rule
	}
	return cp
}

// LoadRules, operatör-tanımlı özel tespit kurallarını JSON dizisinden ayrıştırır.
// Her kural en az id/name/severity taşımalıdır (aksi halde hata). Böylece SOC,
// koda dokunmadan kuruma özgü tespit içeriği ekleyebilir.
func LoadRules(r io.Reader) ([]Rule, error) {
	var rules []Rule
	if err := json.NewDecoder(r).Decode(&rules); err != nil {
		return nil, fmt.Errorf("detect: kural JSON ayrıştırılamadı: %w", err)
	}
	for i, rr := range rules {
		if rr.ID == "" || rr.Name == "" || rr.Severity == "" {
			return nil, fmt.Errorf("detect: kural[%d] eksik alan (id/name/severity zorunlu)", i)
		}
		if rr.MessageRegex != "" {
			if _, err := regexp.Compile(rr.MessageRegex); err != nil {
				return nil, fmt.Errorf("detect: kural[%d] (%s) message_regex geçersiz: %w", i, rr.ID, err)
			}
		}
		if rr.MinSeverity != "" && sevRank[rr.MinSeverity] == 0 {
			return nil, fmt.Errorf("detect: kural[%d] (%s) geçersiz min_severity %q", i, rr.ID, rr.MinSeverity)
		}
		if st := strings.ToLower(strings.TrimSpace(rr.Status)); st != "" && st != "active" && st != "draft" && st != "retired" {
			return nil, fmt.Errorf("detect: kural[%d] (%s) geçersiz status %q (draft|active|retired)", i, rr.ID, rr.Status)
		}
		if rr.WithinBytes < 0 {
			return nil, fmt.Errorf("detect: kural[%d] (%s) within_bytes >= 0 olmalı", i, rr.ID)
		}
		if rr.WithinBytes > 0 && len(rr.Sequence) < 2 {
			return nil, fmt.Errorf("detect: kural[%d] (%s) within_bytes için sequence en az 2 literal içermeli", i, rr.ID)
		}
		if th := rr.Threshold; th != nil {
			if th.Count < 1 {
				return nil, fmt.Errorf("detect: kural[%d] (%s) threshold.count >= 1 olmalı", i, rr.ID)
			}
			if th.Seconds < 1 {
				return nil, fmt.Errorf("detect: kural[%d] (%s) threshold.seconds >= 1 olmalı", i, rr.ID)
			}
			switch strings.ToLower(strings.TrimSpace(th.Track)) {
			case "", "device", "tenant", "global":
			default:
				return nil, fmt.Errorf("detect: kural[%d] (%s) geçersiz threshold.track %q (device|tenant|global)", i, rr.ID, th.Track)
			}
		}
		if b := rr.Bits; b != nil {
			if len(b.Require) == 0 && len(b.RequireNot) == 0 && len(b.Set) == 0 {
				return nil, fmt.Errorf("detect: kural[%d] (%s) bits en az bir require/require_not/set içermeli", i, rr.ID)
			}
			if b.TTLSeconds < 0 {
				return nil, fmt.Errorf("detect: kural[%d] (%s) bits.ttl_seconds >= 0 olmalı", i, rr.ID)
			}
			switch strings.ToLower(strings.TrimSpace(b.Track)) {
			case "", "device", "tenant", "global":
			default:
				return nil, fmt.Errorf("detect: kural[%d] (%s) geçersiz bits.track %q (device|tenant|global)", i, rr.ID, b.Track)
			}
		}
	}
	return rules, nil
}

// LoadRulesFile, bir dosyadan özel kural seti yükler.
func LoadRulesFile(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadRules(f)
}

// ErrBadSignature, kural dosyası imzası doğrulanamadığında döner.
var ErrBadSignature = errors.New("detect: kural imzası GEÇERSİZ — yükleme reddedildi")

// LoadRulesFileSigned, tespit kurallarını YALNIZ Ed25519 imzası doğrulandıktan
// sonra yükler (kurcalamaya karşı; anomali modeli / YARA kuralı imzasıyla aynı
// desen). İmza, kural JSON baytları üzerinedir ve `<path>.sig` dosyasında base64
// beklenir. Kuralları yazabilen ama imzalayamayan bir saldırgan, tespit içeriğini
// sessizce değiştiremez (fail-closed).
func LoadRulesFileSigned(path string, pub ed25519.PublicKey) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sigB64, err := os.ReadFile(path + ".sig")
	if err != nil {
		return nil, fmt.Errorf("detect: imza dosyası (%s.sig) okunamadı: %w", path, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return nil, fmt.Errorf("detect: imza base64 çözülemedi: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, sig) {
		return nil, ErrBadSignature
	}
	return LoadRules(bytes.NewReader(data))
}

// WithDefaults, yerleşik kurallara özel kuralları ekler (yerleşikler önce
// değerlendirilir, özel kurallar sonra).
func WithDefaults(extra []Rule) []Rule {
	return append(DefaultRules(), extra...)
}

// MITRE ATT&CK teknikleri (mitre paketiyle tutarlı).
var (
	tImpairDefenses = mitre.Technique{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion"}
	tScripting      = mitre.Technique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"}
	tSupplyChain    = mitre.Technique{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "Initial Access"}
	tUserExecution  = mitre.Technique{ID: "T1204", Name: "User Execution", Tactic: "Execution"}
	tProcInjection  = mitre.Technique{ID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion"}
	tNetworkDiscov  = mitre.Technique{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery"}
	tAutostart      = mitre.Technique{ID: "T1547", Name: "Boot or Logon Autostart Execution", Tactic: "Persistence"}
	tAppLayerC2     = mitre.Technique{ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control"}
	tExfilAltProto  = mitre.Technique{ID: "T1048", Name: "Exfiltration Over Alternative Protocol", Tactic: "Exfiltration"}
	tIndicatorRem   = mitre.Technique{ID: "T1070", Name: "Indicator Removal", Tactic: "Defense Evasion"}
	tIngressTool    = mitre.Technique{ID: "T1105", Name: "Ingress Tool Transfer", Tactic: "Command and Control"}
)

// DefaultRules, yerleşik tespit kural setidir. Ajanın gerçekte ürettiği olay
// kategorileri/mesajlarına dayanır.
func DefaultRules() []Rule {
	return []Rule{
		{ID: "KUT-0001", Name: "Ajan kurcalama girişimi", Category: "SECURITY",
			Contains: []string{"kurcalama"}, Severity: "CRITICAL", Technique: tImpairDefenses},
		{ID: "KUT-0002", Name: "İmzasız/sahte script reddedildi", Category: "SECURITY",
			Contains: []string{"script"}, Severity: "HIGH", Technique: tScripting},
		{ID: "KUT-0003", Name: "Sahte/bozuk OTA güncelleme reddedildi", Category: "SECURITY",
			Contains: []string{"güncelleme"}, Severity: "HIGH", Technique: tSupplyChain},
		{ID: "KUT-0004", Name: "Davranışsal anomali", Category: "SECURITY",
			Contains: []string{"anomali"}, Severity: "HIGH", Technique: tProcInjection},
		{ID: "KUT-0005", Name: "Yasaklı süreç yürütmesi", Category: "POLICY_VIOLATION",
			Severity: "HIGH", Technique: tUserExecution},
		{ID: "KUT-0006", Name: "Ağ hizmet keşfi", Category: "NETWORK_DISCOVERY",
			Severity: "LOW", Technique: tNetworkDiscov},
		// v2: PROCESS telemetrisi üzerinde regex-tabanlı şüpheli-araç tespiti
		// (saldırgan araçları / yaşam-alanı-dışı ikili kullanımı).
		{ID: "KUT-0007", Name: "Şüpheli süreç/araç yürütmesi", Category: "PROCESS",
			MessageRegex: `mimikatz|psexec|\bnc\.exe|\bncat|powershell.*(-enc|-encodedcommand)|certutil.*-urlcache|rundll32.*javascript|regsvr32.*scrobj`,
			Severity:     "HIGH", Technique: tScripting},
		// v2: yeni telemetri türleri için adlandırılmış kurallar (kapsam genişletme).
		{ID: "KUT-0008", Name: "Kalıcılık (autostart) girdisi", Category: "POLICY_VIOLATION",
			Contains: []string{"kalıcılık"}, Severity: "HIGH", Technique: tAutostart},
		{ID: "KUT-0009", Name: "Dosya bütünlüğü değişikliği (FIM)", Category: "SECURITY",
			Contains: []string{"dosya bütünlüğü"}, Severity: "MEDIUM", Technique: tIndicatorRem},
		{ID: "KUT-0010", Name: "DLP — hassas veri sızıntısı", Category: "SECURITY",
			Contains: []string{"hassas veri"}, Severity: "HIGH", Technique: tExfilAltProto},
		{ID: "KUT-0011", Name: "DGA-şüpheli DNS sorgusu", Category: "SECURITY",
			Contains: []string{"dga"}, Severity: "HIGH", Technique: tAppLayerC2},
		{ID: "KUT-0012", Name: "İçerik-tarama (YARA) eşleşmesi", Category: "SECURITY",
			Contains: []string{"içerik-tarama"}, Severity: "HIGH", Technique: tIngressTool},
		{ID: "KUT-0013", Name: "Yanal hareket / iç-ağ tarama", Category: "SECURITY",
			Contains: []string{"yanal hareket"}, Severity: "HIGH", Technique: tNetworkDiscov},
		{ID: "KUT-0014", Name: "DNS tünelleme / veri sızdırma", Category: "SECURITY",
			Contains: []string{"dns tünelleme"}, Severity: "HIGH", Technique: tAppLayerC2},
	}
}
