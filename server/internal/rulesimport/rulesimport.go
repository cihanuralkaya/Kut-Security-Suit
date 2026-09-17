// Package rulesimport, topluluk IDS imzalarının UÇ-NOKTAYA UYGULANABİLİR
// alt kümesini KUT yerel tespit kural modeline (detect.Rule) çevirir. Böylece
// kuruluşlar yaygın IDS içerik-tabanlı içeriğini koda dokunmadan içe aktarabilir.
//
// KAPSAM (dürüst alt küme): KUT uç-nokta olay METNİ üzerinde çalıştığından, yalnız
// içerik/örüntü-tabanlı anahtar kelimeler eşlenir:
//   - msg → Name, sid → ID, rev → Version, classtype/priority → Severity,
//     reference → References
//   - content:"x" → Contains; content:!"x" → Absent (negatif). Aralarında
//     within/distance varsa SIRALI kabul edilip Sequence(+WithinBytes)'e eşlenir.
//   - pcre:"/re/flags" → MessageRegex (Go RE2 ile derlenemezse kural atlanır)
//   - threshold/detection_filter (type threshold|both) → Threshold
//   - flowbits:set/isset → Bits.Set/Require
//
// DESTEKLENMEYEN (güvenle yok sayılır ya da kural atlanır; sessizce YANLIŞ içe
// aktarma YOK): paket/akış konumu (offset/depth/dsize), byte_test/byte_jump, ham
// protokol tamponları, flowbits isnotset/unset/toggle, pass eylemi. Bağımlılıksız.
package rulesimport

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"kut.corp/suite/server/internal/detect"
)

var (
	// ErrNotRule, satır bir kural değilse (yorum/boş/paren yok) döner.
	ErrNotRule = errors.New("rulesimport: kural değil")
	// ErrUnsupported, kural yalnız desteklenmeyen yapılar içerdiğinde döner.
	ErrUnsupported = errors.New("rulesimport: desteklenmeyen yapı")
	// ErrEmptyRule, çevrilen kuralın hiç eşleşme koşulu olmadığında döner.
	ErrEmptyRule = errors.New("rulesimport: boş kural (eşleşme koşulu yok)")
)

// Convert, tek bir IDS kural satırını bir detect.Rule'a çevirir.
func Convert(line string) (detect.Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return detect.Rule{}, ErrNotRule
	}
	open := strings.IndexByte(line, '(')
	closeIdx := strings.LastIndexByte(line, ')')
	if open < 0 || closeIdx < open {
		return detect.Rule{}, ErrNotRule
	}
	header := strings.Fields(strings.TrimSpace(line[:open]))
	if len(header) > 0 && strings.EqualFold(header[0], "pass") {
		return detect.Rule{}, fmt.Errorf("%w: pass eylemi (tespit değil)", ErrUnsupported)
	}
	opts, err := splitOptions(line[open+1 : closeIdx])
	if err != nil {
		return detect.Rule{}, err
	}
	return buildRule(opts)
}

// option, ayrıştırılmış tek bir kural seçeneğidir (key ve —varsa— value).
type option struct {
	key string
	val string
}

// splitOptions, seçenek bloğunu ';' ile böler ama ÇİFT TIRNAK içindeki ';' böler
// saymaz (\" kaçışı tırnağı değiştirmez). Her seçeneği key[:value] olarak ayırır.
func splitOptions(s string) ([]option, error) {
	var opts []option
	var buf strings.Builder
	inQuote := false
	flush := func() {
		tok := strings.TrimSpace(buf.String())
		buf.Reset()
		if tok == "" {
			return
		}
		k, v, hasVal := strings.Cut(tok, ":")
		o := option{key: strings.ToLower(strings.TrimSpace(k))}
		if hasVal {
			o.val = strings.TrimSpace(v)
		}
		opts = append(opts, o)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s): // kaçış: sonraki baytı olduğu gibi al
			buf.WriteByte(c)
			buf.WriteByte(s[i+1])
			i++
		case c == '"':
			inQuote = !inQuote
			buf.WriteByte(c)
		case c == ';' && !inQuote:
			flush()
		default:
			buf.WriteByte(c)
		}
	}
	flush()
	if len(opts) == 0 {
		return nil, ErrNotRule
	}
	return opts, nil
}

// buildRule, ayrıştırılmış seçeneklerden bir detect.Rule kurar.
func buildRule(opts []option) (detect.Rule, error) {
	var r detect.Rule
	var contains, absent []string
	sequenceMode := false
	maxWithin := 0
	var bits detect.BitSpec

	for _, o := range opts {
		switch o.key {
		case "msg":
			r.Name = unquote(o.val)
		case "sid":
			if n := strings.TrimSpace(o.val); n != "" {
				r.ID = "rulesimport:" + n
			}
		case "rev":
			if n, err := strconv.Atoi(strings.TrimSpace(o.val)); err == nil && n > 0 {
				r.Version = strconv.Itoa(n) + ".0.0"
			}
		case "content":
			val := strings.TrimSpace(o.val)
			neg := strings.HasPrefix(val, "!")
			val = unquote(strings.TrimPrefix(val, "!"))
			if val == "" {
				continue
			}
			if neg {
				absent = append(absent, val)
			} else {
				contains = append(contains, val)
			}
		case "within":
			sequenceMode = true
			if n, err := strconv.Atoi(strings.TrimSpace(o.val)); err == nil && n > maxWithin {
				maxWithin = n
			}
		case "distance":
			sequenceMode = true // sıra önemli (asgari-boşluk modellenmez)
		case "pcre":
			re := extractPCRE(o.val)
			if re == "" {
				return detect.Rule{}, fmt.Errorf("%w: pcre biçimi", ErrUnsupported)
			}
			if _, err := regexp.Compile("(?i)" + re); err != nil {
				return detect.Rule{}, fmt.Errorf("%w: pcre Go RE2 ile derlenemedi", ErrUnsupported)
			}
			r.MessageRegex = re
		case "classtype":
			if s := classtypeSeverity(o.val); s != "" && r.Severity == "" {
				r.Severity = s
			}
		case "priority":
			if r.Severity == "" {
				r.Severity = prioritySeverity(o.val)
			}
		case "reference":
			r.References = append(r.References, strings.TrimSpace(o.val))
		case "threshold", "detection_filter":
			if th := parseThreshold(o.val); th != nil {
				r.Threshold = th
			}
		case "flowbits", "xbits":
			applyFlowbits(o.val, &bits)
		default:
			// Desteklenmeyen anahtar kelime: güvenle yok say (nocase, flow, offset,
			// depth, dsize, byte_test, metadata, ... — eşleşmeyi genişletmez/daraltmaz
			// ya da uç-noktaya uygulanamaz).
		}
	}

	if r.Severity == "" {
		r.Severity = "MEDIUM"
	}
	if r.ID == "" {
		r.ID = "rulesimport:" + slug(r.Name)
	}
	if strings.TrimSpace(r.Name) == "" {
		r.Name = "rulesimport kuralı"
	}
	if len(bits.Set) > 0 || len(bits.Require) > 0 || len(bits.RequireNot) > 0 {
		r.Bits = &bits
	}
	if sequenceMode && len(contains) > 0 {
		r.Sequence = contains
		r.WithinBytes = maxWithin
	} else {
		r.Contains = contains
	}
	r.Absent = absent

	if len(r.Contains) == 0 && len(r.Sequence) == 0 && r.MessageRegex == "" && len(r.Absent) == 0 {
		return detect.Rule{}, ErrEmptyRule
	}
	return r, nil
}

// unquote, çift tırnakları soyar ve IDS içerik kaçışlarını (\; \" \\) çözer.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")
	s = strings.ReplaceAll(s, "\\;", ";")
	s = strings.ReplaceAll(s, "\\\"", "\"")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

// extractPCRE, `"/pattern/flags"` biçiminden pattern'i çıkarır (flags atılır; motor
// zaten (?i) uygular). Biçim tanınmazsa "" döner.
func extractPCRE(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "\"")
	v = strings.TrimSuffix(v, "\"")
	v = strings.TrimPrefix(v, "!") // negatif pcre: pattern'i al (dışlama modellenmez, yok sayılır)
	if !strings.HasPrefix(v, "/") {
		return ""
	}
	last := strings.LastIndexByte(v, '/')
	if last <= 0 {
		return ""
	}
	return v[1:last]
}

// classtypeSeverity, yaygın IDS classtype'larını KUT önem düzeyine eşler.
func classtypeSeverity(ct string) string {
	switch strings.ToLower(strings.TrimSpace(ct)) {
	case "trojan-activity", "targeted-activity", "successful-admin", "successful-user",
		"credential-theft", "malware-cnc", "command-and-control", "exploit-kit":
		return "CRITICAL"
	case "attempted-admin", "attempted-user", "web-application-attack", "shellcode-detect",
		"attempted-dos", "denial-of-service", "policy-violation":
		return "HIGH"
	case "bad-unknown", "attempted-recon", "suspicious-filename-detect",
		"suspicious-login", "unusual-client-port-connection":
		return "MEDIUM"
	case "not-suspicious", "network-scan", "protocol-command-decode", "misc-activity":
		return "LOW"
	default:
		return ""
	}
}

// prioritySeverity, IDS priority (1=en yüksek) → önem düzeyi.
func prioritySeverity(p string) string {
	switch strings.TrimSpace(p) {
	case "1":
		return "HIGH"
	case "2":
		return "MEDIUM"
	case "3":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// parseThreshold, "type threshold, track by_src, count N, seconds T" çözer. type
// threshold|both → Threshold döner; limit (bizde yok) → nil. track by_src/by_dst →
// device, by_rule → global.
func parseThreshold(v string) *detect.ThresholdSpec {
	fields := map[string]string{}
	for _, part := range strings.Split(v, ",") {
		kv := strings.Fields(strings.TrimSpace(part))
		if len(kv) == 2 {
			fields[strings.ToLower(kv[0])] = strings.ToLower(kv[1])
		}
	}
	switch fields["type"] {
	case "threshold", "both":
	default:
		return nil // limit / bilinmeyen → eşiğe çevirme
	}
	count, _ := strconv.Atoi(fields["count"])
	secs, _ := strconv.Atoi(fields["seconds"])
	if count < 1 || secs < 1 {
		return nil
	}
	track := "device"
	if fields["track"] == "by_rule" {
		track = "global"
	}
	return &detect.ThresholdSpec{Count: count, Seconds: secs, Track: track}
}

// applyFlowbits, "set,name" / "isset,name" / "isnotset,name" ifadelerini BitSpec'e
// ekler. Diğer komutlar (unset/toggle/noalert) modellenmez → yok sayılır.
func applyFlowbits(v string, b *detect.BitSpec) {
	parts := strings.SplitN(v, ",", 2)
	if len(parts) != 2 {
		return
	}
	cmd := strings.ToLower(strings.TrimSpace(parts[0]))
	name := strings.TrimSpace(parts[1])
	if name == "" {
		return
	}
	switch cmd {
	case "set", "set.and.isset": // bazı kurallar "set" kullanır
		b.Set = append(b.Set, name)
	case "isset":
		b.Require = append(b.Require, name)
	case "isnotset":
		b.RequireNot = append(b.RequireNot, name)
	}
}

// slug, msg'den kararlı bir kimlik üretir (harf/rakam korunur, gerisi '-').
func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "kural"
	}
	return out
}

// ConvertMulti, çok-satırlı bir IDS kural dosyasını çevirir. '\' ile biten
// satırlar bir sonrakiyle birleştirilir (satır devamı). Yorumlar/boş satırlar
// atlanır. Başarılı kuralları + atlanan satırların nedenlerini döner (tek bir kötü
// satır tüm içe aktarımı bozmaz).
func ConvertMulti(data []byte) ([]detect.Rule, []string) {
	var rules []detect.Rule
	var skips []string
	seen := map[string]bool{}
	for _, raw := range joinContinuations(string(data)) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := Convert(line)
		if err != nil {
			if !errors.Is(err, ErrNotRule) {
				skips = append(skips, fmt.Sprintf("%.60q: %v", line, err))
			}
			continue
		}
		if seen[r.ID] {
			skips = append(skips, fmt.Sprintf("%.60q: yinelenen id %s", line, r.ID))
			continue
		}
		seen[r.ID] = true
		rules = append(rules, r)
	}
	return rules, skips
}

// joinContinuations, '\' ile biten satırları bir sonrakiyle birleştirir.
func joinContinuations(s string) []string {
	rawLines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	var out []string
	var cur strings.Builder
	for _, ln := range rawLines {
		if strings.HasSuffix(ln, "\\") {
			cur.WriteString(strings.TrimSuffix(ln, "\\"))
			continue
		}
		cur.WriteString(ln)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
