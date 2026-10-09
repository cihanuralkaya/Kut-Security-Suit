package aiprovider

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
)

// LocalInvestigationProvider, SIFIR-AĞ, deterministik bir ModelProvider'dır: soruşturma
// prompt'undaki Incident ID / Category / Message'tan geçerli bir InvestigationReport JSON
// SENTEZLER. Egemenlik varsayılanı: Investigator Restricted hassasiyet kullanır ve router
// Restricted'ı YALNIZ yerel sağlayıcıya yönlendirir (hassas olay metni ana bilgisayarı
// terk etmez) — bu sağlayıcı, DIŞ model olmadan Investigator'ı kullanışlı tutar (aibrain'in
// canlı yerel SOC beyniyle aynı felsefe: anahtar-kelime tabanlı deterministik analiz).
type LocalInvestigationProvider struct{}

// NewLocalInvestigationProvider, deterministik yerel soruşturma sağlayıcısı üretir.
func NewLocalInvestigationProvider() *LocalInvestigationProvider {
	return &LocalInvestigationProvider{}
}

// techKeywords, olay metnindeki anahtar kelimeleri ATT&CK tekniklerine eşler (deterministik).
var techKeywords = []struct {
	re   *regexp.Regexp
	tech string
}{
	{regexp.MustCompile(`(?i)ransom|fidye|\.encrypted|vssadmin.*delete`), "T1486"},
	{regexp.MustCompile(`(?i)mimikatz|lsass|procdump.*lsass|sekurlsa`), "T1003"},
	{regexp.MustCompile(`(?i)-enc\b|-encodedcommand|frombase64string`), "T1027"},
	{regexp.MustCompile(`(?i)certutil`), "T1140"},
	{regexp.MustCompile(`(?i)bitsadmin|start-bitstransfer`), "T1197"},
	{regexp.MustCompile(`(?i)\bwmic\b|invoke-wmimethod|win32_process`), "T1047"},
	{regexp.MustCompile(`(?i)\bnet\s+(user|group|localgroup)\b|whoami\s+/groups`), "T1087"},
	{regexp.MustCompile(`(?i)findstr.*password|cmdkey\s+/list|reg\s+query.*password`), "T1552"},
	{regexp.MustCompile(`(?i)anydesk|teamviewer|screenconnect|ngrok|atera`), "T1219"},
	{regexp.MustCompile(`(?i)rar\s+a|7z\s+a|compress-archive`), "T1560"},
	{regexp.MustCompile(`(?i)disable.*(realtime|defender|windefend)|set-mppreference`), "T1562"},
	{regexp.MustCompile(`(?i)schtasks|scheduled task|zamanlanmış görev`), "T1053"},
	{regexp.MustCompile(`(?i)run key|currentversion\\run|autostart`), "T1547"},
}

var critKeywords = regexp.MustCompile(`(?i)ransom|fidye|lsass|mimikatz|wipe|destroy|exfil`)
var highKeywords = regexp.MustCompile(`(?i)-enc\b|certutil|bitsadmin|disable.*defender|password|anydesk|teamviewer|privilege`)

// Complete, prompt'tan deterministik bir InvestigationReport JSON üretir.
func (p *LocalInvestigationProvider) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	prompt := ""
	if n := len(req.Messages); n > 0 {
		prompt = req.Messages[n-1].Content
	}
	incidentID := extractPromptField(prompt, "Incident ID:")
	category := extractPromptField(prompt, "Category:")
	message := extractPromptMessage(prompt)

	hay := category + " " + message
	var techs []string
	seen := map[string]bool{}
	for _, k := range techKeywords {
		if k.re.MatchString(hay) && !seen[k.tech] {
			techs = append(techs, k.tech)
			seen[k.tech] = true
		}
	}

	severity := "MEDIUM"
	switch {
	case critKeywords.MatchString(hay):
		severity = "CRITICAL"
	case highKeywords.MatchString(hay):
		severity = "HIGH"
	}

	rep := InvestigationReport{
		IncidentID:              incidentID,
		Severity:                severity,
		Summary:                 "Deterministik yerel analiz: " + truncate(firstLine(message), 180),
		RootCause:               deriveRootCause(category, techs),
		MITRETechniques:         techs,
		RecommendedRemediations: deriveRemediations(severity, techs),
		Confidence:              0.55, // deterministik yerel sağlayıcı: orta güven (dış model değil)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return CompletionResponse{}, err
	}
	return CompletionResponse{Content: string(b), Tokens: len(b) / 4}, nil
}

func (p *LocalInvestigationProvider) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	res := make([][]float32, len(texts))
	for i := range texts {
		res[i] = []float32{0, 0, 0}
	}
	return res, nil
}
func (p *LocalInvestigationProvider) Health(ctx context.Context) error { return nil }
func (p *LocalInvestigationProvider) Name() string                     { return "local-deterministic-investigator" }

func deriveRootCause(category string, techs []string) string {
	if len(techs) == 0 {
		return "Belirgin teknik imzası yok; " + def(category, "bilinmeyen kategori") + " olayının bağlamsal incelemesi gerekir."
	}
	return "Gözlenen teknik(ler): " + strings.Join(techs, ", ") + " — " + def(category, "olay") + " bağlamında."
}

func deriveRemediations(severity string, techs []string) []string {
	rem := []string{"Etkilenen cihazın taze olaylarını doğrulama penceresinde yeniden değerlendir (verify döngüsü)."}
	for _, t := range techs {
		switch t {
		case "T1486":
			rem = append(rem, "Cihazı derhal ağdan izole et; yedek bütünlüğünü doğrula (fidye).")
		case "T1003", "T1552":
			rem = append(rem, "Maruz kalan hesapların kimlik bilgilerini döndür; ayrıcalıklı oturumları iptal et.")
		case "T1219":
			rem = append(rem, "Yetkisiz uzaktan-erişim (RMM) aracını kaldır ve giden bağlantısını engelle.")
		case "T1562":
			rem = append(rem, "Güvenlik aracı korumalarını yeniden etkinleştir ve kurcalama kaynağını araştır.")
		}
	}
	if severity == "CRITICAL" {
		rem = append(rem, "Çift-kontrol onayıyla containment (karantina) değerlendir; SOC'u yükselt.")
	}
	return rem
}

func extractPromptField(prompt, label string) string {
	for _, line := range strings.Split(prompt, "\n") {
		if strings.HasPrefix(line, label) {
			return strings.TrimSpace(strings.TrimPrefix(line, label))
		}
	}
	return ""
}

// extractPromptMessage, "Message:" ile "\n\nKnowledge Context:" arasındaki (çok satırlı
// olabilen) olay mesajını çıkarır.
func extractPromptMessage(prompt string) string {
	i := strings.Index(prompt, "Message:")
	if i < 0 {
		return ""
	}
	rest := prompt[i+len("Message:"):]
	if j := strings.Index(rest, "\n\nKnowledge Context:"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
func def(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
