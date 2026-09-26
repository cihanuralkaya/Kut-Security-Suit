# KUT Security Suite — AI Security Brain (vNext P4) Uygulama Planı

Bu belge, `docs/ARCHITECTURE-vNext.md`'de tanımlanan **AI Security Brain** katmanının
(faz **P4**) uygulanabilir teknik planıdır. Amaç, çekirdeğin deterministik + zero-dep
duruşunu **bozmadan** — ML/graph/LLM sinyallerini birer *öneri* ve *risk sinyali*
olarak sisteme sokmaktır.

> **Değişmez ilke (tekrar):** Güvenlik sistemi AI'ı yönetir; AI güvenlik sistemini
> yönetmez. Her AI çıktısı `server/internal/authz` gateway'inin **altında** kalır ve
> asla doğrudan yüksek-etkili aksiyon yürütmez — yalnızca **önerir**.

Bu plan yeni bir asistan tasarımı **değildir**. Mevcut `server/internal/aiassist`
(§27) katmanı — sağlayıcıdan bağımsız `Provider` arayüzü, deterministik
`LocalProvider`, ve `Gate` (politika + insan onayı durum makinesi) — zaten "AI salt
öneri üretir, insan döngüde" sözleşmesini gerçekliyor. P4, bu sözleşmeyi **korelasyon,
graf ve risk füzyonu** düzeyine taşır ve opsiyonel **dış** model servislerini ekler.

---

## 1. Çekirdek ilke ve fail-open sözleşmesi

### 1.1 İki ayrı "fail" yönü

AI katmanı iki farklı şekilde başarısız olabilir; ikisinin de çekirdeği **akıtmaması**
gerekir:

| Başarısızlık | Örnek | Çekirdek davranışı |
|---|---|---|
| **Erişilemezlik** (fail-open) | Dış model servisi down / timeout / env yok | Öneri **boş** döner; enforcement deterministik yolla **devam eder** |
| **Yanılma** (fail-safe) | Model yanlış "izole et" önerir | Öneri authz gateway + insan onayının altında kalır; **kendiliğinden çalışmaz** |

Terminoloji: burada **fail-open**, "AI yokmuş gibi çalışmaya devam et" anlamındadır
(güvenlik enforcement'ı **açık/çalışır** kalır). Yüksek-etkili aksiyon kararı ise her
zaman **fail-closed**'dır (authz reddederse aksiyon olmaz). İkisi çelişmez: AI'ın
*yokluğu* enforcement'ı durdurmaz, AI'ın *önerisi* ise tek başına aksiyon açamaz.

### 1.2 Aksiyon zinciri (değişmez)

```
  Telemetri / Tespit
        │
        ▼
  ┌───────────────┐   opsiyonel, best-effort, timeout'lu
  │  AI Brain      │───────────────► boş sonuç ⇒ çekirdek etkilenmez
  │ (aibrain.*)    │
  └──────┬─────────┘
         │ ÖNERİ (Recommendation / Signal)
         ▼
  riskfusion  ◄── AI çıktısı BİR SİNYAL olarak girer (ağırlıklı, açıklanabilir)
         │
         ▼
  aiassist.Gate  ◄── politika denetimi + İNSAN onayı (durum makinesi)
         │  Actionable() == true ?
         ▼
  authz.Gateway.Authorize()  ◄── TEK güvenlik sınırı (blast-radius, rate-limit, …)
         │  Allow == true ?
         ▼
  response / SOAR  ── aksiyonu YÜRÜTEN katman (AI değil)
```

**Sözleşme maddeleri:**

1. `aibrain` çağrıları **her zaman** `context.Context` + timeout ile yapılır; süre
   aşımı veya hata → **boş** sonuç, çağıran akış devam eder (hata log'lanır, yükseltilmez).
2. AI önerileri authz için `Requester = authz.AI` etiketiyle temsil edilir; bu talepçi
   `HardAutonomousRadius` (varsayılan 3) sert tavanına tabidir ve **onayla bile** aşamaz.
3. `aibrain` paketi **yürütme** API'si içermez. Yalnız `Provider` (öneri üretir) ve
   normalize edici yardımcılar sunar; aksiyonu `response`/SOAR yapar.
4. Varsayılan sağlayıcı deterministik **LOCAL stub**'tır (dış servis yoksa). Bu,
   "AI dikişi zero-dep ile derlenir/test edilir" garantisini CI'da kanıtlar.

---

## 2. Go-tarafı adaptör sözleşmesi — `server/internal/aibrain` (yeni)

`aibrain`, çekirdeğin opsiyonel AI servisleriyle konuştuğu **tek** sınırdır.
`aiassist`'ten farkı: `aiassist` serbest-metin SOC asistanıdır (§27, olduğu gibi
kalır); `aibrain` ise **yapısal** sinyaller (sekans skoru, graf anomalisi, risk
açıklaması) üretir ve doğrudan `riskfusion`/`correlate`/`entitygraph` akışlarını besler.

### 2.1 `Provider` arayüzü (taslak imzalar)

```go
package aibrain

import (
    "context"
    "time"

    "kut.corp/suite/server/internal/entitygraph"
    "kut.corp/suite/server/internal/riskfusion"
)

// Provider, opsiyonel AI arka ucunu soyutlar. TÜM metotlar salt-öneri üretir;
// hiçbiri aksiyon yürütmez. Her metot fail-open'dır: hata/timeout → boş sonuç +
// err; çağıran boş sonucu "AI yok" gibi ele alır ve deterministik yola devam eder.
type Provider interface {
    // SummarizeIncident, bir incident'in insan-okunur özetini üretir (LLM veya
    // deterministik). Yalnız bilgilendiricidir; aksiyon önermez.
    SummarizeIncident(ctx context.Context, in IncidentInput) (Summary, error)

    // SuggestTriage, bir uyarı/incident için triyaj önerisi (öncelik, olası FP,
    // önerilen sonraki adım) döner. Öneriler aiassist.Gate + authz altında kalır.
    SuggestTriage(ctx context.Context, in TriageInput) (Triage, error)

    // ScoreSequence, bir olay/komut dizisinin "nadirlik/anomali" skorunu (0..100)
    // ve gerekçesini döner. Deterministik n-gram/Markov (LOCAL) veya transformer
    // (dış) ile. Çıktı riskfusion'a BİR SİNYAL olarak girer.
    ScoreSequence(ctx context.Context, in SequenceInput) (SequenceScore, error)

    // ScoreGraph, entitygraph üzerindeki bir alt-graf/komşuluk için yapısal
    // anomali skoru döner (deterministik ölçütler veya dış GNN). riskfusion sinyali.
    ScoreGraph(ctx context.Context, in GraphInput) (GraphScore, error)

    // ExplainRisk, bir riskfusion.Result'ı doğal dile çevirir (neden bu skor?);
    // açıklanabilirliği bozmaz, mevcut Contributions'ı zenginleştirir.
    ExplainRisk(ctx context.Context, res riskfusion.Result) (Explanation, error)

    // Health, sağlayıcının hazır olup olmadığını hızlıca bildirir (probe).
    Health(ctx context.Context) error
}
```

Yardımcı tipler (özet imzalar):

```go
type IncidentInput struct {
    IncidentID string
    Device     string
    Technique  string            // MITRE ATT&CK ör. T1059
    Severity   string
    Events     []string          // normalize edilmiş kısa olay satırları
    Context    map[string]string
}

type Summary struct {
    Text       string
    Confidence float64            // 0..1
    Source     string             // "local" | "llm:<model>" — denetlenebilirlik
}

type TriageInput struct {
    IncidentID string
    Signals    []riskfusion.Signal // mevcut deterministik sinyaller
    Events     []string
}

type Triage struct {
    Priority     string           // LOW|MEDIUM|HIGH|CRITICAL (öneri)
    LikelyFP     bool
    NextSteps    []string         // salt öneri
    Confidence   float64
    Source       string
}

// SequenceInput, sıralı bir olay dizisidir (ör. süreç ağacı, komut geçmişi).
type SequenceInput struct {
    Tokens []string               // deterministik olarak sıralı token'lar
    Kind   string                 // "process" | "command" | "auth"
}

type SequenceScore struct {
    Score      float64            // 0..100 nadirlik/anomali
    Rationale  string             // hangi geçiş(ler) nadir — açıklanabilirlik
    Source     string
}

type GraphInput struct {
    Focus    entitygraph.Node     // merkez düğüm
    MaxDepth int
    // Not: Graph'ın kendisi çağıran tarafça okunur; Provider yalnız çıkarılmış
    // metrik/komşuluk özetini alır (dış servise ham graf sızdırılmaz — §5.4).
    Features GraphFeatures
}

type GraphFeatures struct {
    FanOut, FanIn int
    RareEdges     int             // deterministik nadirlik ön-hesabı
    NewNodeRatio  float64
}

type GraphScore struct {
    Score     float64             // 0..100
    Rationale string
    Source    string
}

type Explanation struct {
    Text   string
    Source string
}
```

### 2.2 Fail-open sarmalayıcı (çekirdeğin gördüğü tek yüz)

`Provider`'ı doğrudan çağırmak yerine çekirdek, timeout + boş-sonuç garantisi veren
bir `Brain` sarmalayıcısı kullanır:

```go
// Brain, bir Provider'ı fail-open semantiğiyle sarar. Provider nil ise (dış AI
// yapılandırılmamış) TÜM çağrılar anında boş sonuç döner — çekirdek akmaz.
type Brain struct {
    p       Provider      // nil olabilir
    timeout time.Duration // her çağrı için üst sınır (ör. 800ms)
}

func New(p Provider, timeout time.Duration) *Brain { /* p==nil güvenli */ }

// ScoreSequence, Provider yoksa/timeout/hata durumunda {} , false döner.
// ok==false ⇒ çağıran deterministik yola devam eder, hiçbir sinyal EKLEMEZ.
func (b *Brain) ScoreSequence(ctx context.Context, in SequenceInput) (SequenceScore, bool) {
    if b == nil || b.p == nil {
        return SequenceScore{}, false
    }
    cctx, cancel := context.WithTimeout(ctx, b.timeout)
    defer cancel()
    s, err := b.p.ScoreSequence(cctx, in)
    if err != nil {
        return SequenceScore{}, false // fail-open: sessizce yut, log'la
    }
    return s, true
}
// Diğer metotlar için de aynı desen (SummarizeIncident, SuggestTriage, …).
```

Böylece **çağıran kod tek bir kod yolu** yazar: `if s, ok := brain.ScoreSequence(...); ok { füzyona ekle }`.
`ok == false` her zaman "AI yokmuş gibi davran" demektir.

### 2.3 Varsayılan LOCAL sağlayıcı

`aibrain.LocalProvider` — sıfır ağ, deterministik. Her metodu deterministik bir
karşılıkla doldurur:

- `ScoreSequence`: paket-içi **n-gram/Markov nadirlik** (bkz. P4.1).
- `ScoreGraph`: `GraphFeatures` üzerinde deterministik eşik/ağırlık.
- `SummarizeIncident` / `SuggestTriage`: mevcut `aiassist.LocalProvider` sezgilerini
  yeniden kullanır (kod tekrarını önlemek için `aiassist`'e delege edebilir).
- `ExplainRisk`: `riskfusion.Result.Contributions`'ı şablonla düz metne çevirir.

LOCAL sağlayıcı **varsayılandır**; dış servis yalnız env ile devreye girer (§5.5).

---

## 3. P4 alt-fazları (P4.1 → P4.5)

Her alt-faz **iki aşamalıdır**: önce **deterministik Go** (çekirdek, zero-dep,
CI-doğrulanabilir), sonra **opsiyonel dış** model (env ile). Deterministik aşama tek
başına üretim değeri üretir ve dış aşama olmadan da tam çalışır.

### P4.1 — Sekans nadirliği (deterministik) → Transformer (opsiyonel)

| Alan | İçerik |
|---|---|
| **Amaç** | Süreç ağaçları / komut dizileri / auth dizilerindeki **nadir geçişleri** yakalamak (yeni, hiç görülmemiş davranış = potansiyel saldırı). |
| **Aşama 1 (Go, çekirdek)** | `aibrain` içinde **n-gram/Markov nadirlik** modeli. Geçmiş dizilerden bigram/trigram geçiş sayıları öğrenilir; bir dizinin skoru = düşük-olasılıklı geçişlerin ağırlıklı toplamı (ör. `-log P(tₙ|tₙ₋₁)`). Tamamen deterministik, bellek-içi, `map[string]int` sayaçları. |
| **Aşama 2 (dış, opsiyonel)** | `services/ai-sequence/` — küçük bir transformer/RNN, aynı `ScoreSequence` kontratını HTTP üzerinden gerçekler. Model dilinden bağımsız (Python + PyTorch/ONNX). |
| **Servis sınırı** | Aşama 1 **Go-içi**; Aşama 2 **dış HTTP** servis. |
| **Veri akışı** | `entitygraph` (`ChildOf`, `Ran` kenarları) veya süreç telemetrisi → token dizisi → `ScoreSequence` → `riskfusion.Signal{Name:"seq"}`. |
| **Tüketir / besler** | Tüketir: süreç/komut telemetrisi, `entitygraph`. Besler: `riskfusion`, `correlate` (yüksek nadirlik → incident önceliği). |
| **Risk** | Yeni ortamda "her şey nadir" (cold-start). Azaltma: eşik + minimum-gözlem sayısı; skor yalnız *sinyal*, tek başına aksiyon açmaz. |
| **CI-doğrulanabilirlik** | Deterministik: sabit eğitim dizileri → sabit skor. Golden-test yazılır; `CGO_ENABLED=0` derlenir. |

Örnek imza (aşama 1):

```go
// SeqModel, deterministik n-gram nadirlik modelidir (LOCAL ScoreSequence çekirdeği).
type SeqModel struct{ /* order int; counts map[string]int; totals map[string]int */ }
func NewSeqModel(order int) *SeqModel
func (m *SeqModel) Train(seqs [][]string)            // geçmişten öğren (deterministik)
func (m *SeqModel) Score(tokens []string) (score float64, rarest string)
```

### P4.2 — Graf anomalisi (deterministik) → GNN (opsiyonel)

| Alan | İçerik |
|---|---|
| **Amaç** | `entitygraph` üzerinde yapısal anomali: ani fan-out (bir cihazın çok sayıda yeni IP'ye bağlanması), köprü düğümler (lateral hareket), nadir kenar örüntüleri. |
| **Aşama 1 (Go, çekirdek)** | `entitygraph`'ın mevcut `Targets/Sources/Reachable` API'siyle **deterministik metrikler**: derece, `Edge.Count`/`FirstSeen` nadirliği, komşuluk yeniliği. `GraphFeatures` bunlardan hesaplanır; `ScoreGraph` bir eşik/ağırlık fonksiyonudur. |
| **Aşama 2 (dış, opsiyonel)** | `services/ai-graph/` — GNN (embedding + anomali). Çekirdek ham grafı sızdırmaz; yalnız çıkarılmış özellik/komşuluk vektörünü gönderir (§5.4). |
| **Servis sınırı** | Aşama 1 **Go-içi** (entitygraph komşusu); Aşama 2 **dış gRPC/HTTP**. |
| **Veri akışı** | `entitygraph.Reachable(focus, depth)` → `GraphFeatures` → `ScoreGraph` → `riskfusion.Signal{Name:"graph"}`. |
| **Tüketir / besler** | Tüketir: `entitygraph`. Besler: `riskfusion`, hunting/pivot yüzeyi, `casemgmt` (ilişkili varlık önerisi). |
| **Risk** | Graf büyüdükçe maliyet. Azaltma: `Reachable` derinlik sınırı (2-3) + `Prune`. |
| **CI-doğrulanabilirlik** | Deterministik graf kurulumu → sabit skor; entitygraph zaten test-dostu. |

### P4.3 — LLM SOC Analyst (opsiyonel dış API)

| Alan | İçerik |
|---|---|
| **Amaç** | Incident özeti, saldırı hikâyesi, triyaj gerekçesi, sorgu üretimi — doğal dilde. `aiassist`'in §27 görevleriyle örtüşür; P4.3 bunları **dış** modelle güçlendirir. |
| **Aşama 1 (Go, çekirdek)** | Zaten var: `aiassist.LocalProvider` (deterministik özet/MITRE/FP). `aibrain.SummarizeIncident/SuggestTriage` LOCAL yolda buna delege eder. |
| **Aşama 2 (dış, opsiyonel)** | `services/ai-llm/` — harici model API'sine (self-host veya sağlayıcı) köprü. Kontrat: incident bağlamı → yapılandırılmış özet/triyaj. |
| **Servis sınırı** | **Dış HTTP** servis; kimlik/anahtar servis içinde, çekirdekte değil. |
| **Veri akışı** | `correlate`/`casemgmt` → `IncidentInput` → `SummarizeIncident` → SOC yüzeyinde gösterim (salt bilgi) **veya** `SuggestTriage` → `aiassist.Gate`. |
| **Tüketir / besler** | Tüketir: `correlate`, `casemgmt`, `entitygraph`. Besler: SOC Command Center UI, `aiassist.Gate` (öneri → onay). |
| **Risk** | Prompt-injection (telemetri içeriği modele gider), veri sızıntısı, halüsinasyon. Azaltma: §5.4 (redaksiyon, allowlist), çıktı **asla** doğrudan aksiyon değil; P5 tespiti. |
| **CI-doğrulanabilirlik** | Dış API mock'lanır; kontrat testi (şema uyumu). LOCAL yol tam deterministik test edilir. |

### P4.4 — Risk füzyonu birleşimi (çekirdek yapıştırıcı)

| Alan | İçerik |
|---|---|
| **Amaç** | P4.1–P4.3 çıktılarını mevcut `riskfusion` motoruna **birer açıklanabilir sinyal** olarak sokmak. |
| **Aşama** | Yalnız Go, çekirdek (dış bağımlılık yok). Ayrıntı §4. |
| **Servis sınırı** | Go-içi. |
| **Veri akışı** | `aibrain.*Score` → `riskfusion.Signal` → `riskfusion.Fuse` → `Result.Contributions`. |
| **Risk** | AI sinyalinin ağırlığı çok yüksekse determinizm gölgelenir. Azaltma: AI sinyalleri düşük başlangıç ağırlığı + `Counterfactual` ile denetim. |
| **CI-doğrulanabilirlik** | `Fuse`/`Counterfactual` zaten deterministik ve testli; AI sinyali eklendiğinde katkı toplamı = skor invaryantı korunur. |

### P4.5 — Dış servis omurgası (iskele + bağlanabilirlik)

| Alan | İçerik |
|---|---|
| **Amaç** | `services/ai-*` dizinlerini, sağlık/timeout kontratını ve env-tabanlı opsiyonel bağlamayı standardize etmek (§5). |
| **Aşama** | Go tarafı: `aibrain` HTTP/gRPC istemcisi (LOCAL fallback). Servis tarafı: iskele. |
| **CI-doğrulanabilirlik** | İstemci mock sunucuya karşı; servis yokken LOCAL yol yeşil. |

---

## 4. Risk füzyonu birleşimi (açıklanabilirlik korunur)

`riskfusion` doğrusal, ağırlıklı-ortalama ve **kapalı-form açıklanabilir** bir motordur
(`Skor = Σ(wᵢ·sᵢ)/Σwᵢ`, her sinyalin katkısı `Pointsᵢ = wᵢ·sᵢ/Σw`). AI çıktıları bu
modeli **değiştirmez**; yalnızca yeni `Signal` satırları olarak katılır:

```go
signals := []riskfusion.Signal{
    {Name: "ioc",  Score: 90, Weight: 3.0},   // mevcut deterministik
    {Name: "ueba", Score: 60, Weight: 2.0},   // mevcut deterministik
    {Name: "vuln", Score: 40, Weight: 1.0},   // mevcut deterministik
}
// AI sinyalleri yalnızca ok==true iken eklenir (fail-open):
if s, ok := brain.ScoreSequence(ctx, seqIn); ok {
    signals = append(signals, riskfusion.Signal{
        Name: "seq", Score: s.Score, Weight: 0.8, // düşük başlangıç ağırlığı
    })
}
if g, ok := brain.ScoreGraph(ctx, graphIn); ok {
    signals = append(signals, riskfusion.Signal{
        Name: "graph", Score: g.Score, Weight: 0.8,
    })
}
res := riskfusion.Fuse(signals)
```

Açıklanabilirlik garantileri:

- **Katkı ayrıştırması korunur:** `res.Contributions` içinde `seq`/`graph` de birer
  satır olur; `Σ Points = Score` invaryantı bozulmaz.
- **Counterfactual denetimi:** `riskfusion.Counterfactual(signals, "seq")` ile "AI
  sinyali olmasaydı skor ne olurdu?" her zaman hesaplanabilir — AI'ın skora etkisi
  **niceliksel** ve denetlenebilir kalır.
- **Fail-open nötrlüğü:** AI sinyali yoksa (`ok==false`) füzyon **hiç değişmeden**
  deterministik sinyallerle çalışır; skor determinizmi tam korunur.
- **Ağırlık disiplini:** AI sinyalleri düşük ağırlıkla başlar; ağırlık artışı yalnız
  gözlemsel doğrulama (FP oranı) sonrası ve **politika** olarak yapılır — kod değil.

```
  deterministik sinyaller ─┐
                           ├─► riskfusion.Fuse ─► Result{Score, Contributions, Top}
  AI sinyalleri (opsiyonel)┘        (kapalı-form, açıklanabilir; AI yoksa değişmez)
```

---

## 5. Dış AI servisi iskelet önerisi

### 5.1 Dizin yapısı

```
services/
  ai-sequence/          # P4.1 aşama 2 — transformer sekans skoru
    README.md
    pyproject.toml      # veya requirements.txt (dış bağımlılıklar SERBEST)
    app/
      main.py           # HTTP sunucu (FastAPI/uvicorn) — /health, /score
      model.py
    Dockerfile
  ai-graph/             # P4.2 aşama 2 — GNN graf anomalisi
  ai-llm/               # P4.3 aşama 2 — LLM SOC analyst köprüsü
proto/
  aibrain.proto         # gRPC seçilirse ortak kontrat (opsiyonel)
```

Dış servisler **ayrı** derleme/dağıtım birimidir; Go `go.mod`'una **hiçbir** giriş
eklemezler. Dil serbesttir (öneri: Python).

### 5.2 Dil ve teknoloji

- **Sekans/GNN:** Python + PyTorch veya ONNX Runtime (dış servis içinde CGo/native
  serbest — çekirdeği etkilemez; krş. `docs/ONNX.md`'nin çekirdek-içi kısıtı).
- **LLM:** Python köprü servisi (self-host model veya sağlayıcı API'si servis içinde).
- **Taşıma:** varsayılan **HTTP+JSON** (basit, mock'lanabilir). Yüksek hacim gerekirse
  **gRPC** (`proto/aibrain.proto`) opsiyonel.

### 5.3 HTTP kontratı (örnek — `ai-sequence`)

```
GET  /health            → 200 {"status":"ok","model":"seq-v1"}      (timeout'lu probe)
POST /v1/score/sequence → 200 {"score":0..100,"rationale":"...","source":"llm:seq-v1"}
     body: {"tokens":["explorer.exe","powershell.exe","...",],"kind":"process"}
```

- Her uç **timeout** ve **boyut sınırı** (payload cap) uygular.
- Hata/aşırı yük → 5xx; Go istemcisi bunu **fail-open** olarak ele alır (boş sonuç).
- Kimlik: servis-içi API anahtarı/mTLS; anahtar **çekirdekte değil**, servis env'inde.

### 5.4 Veri sınırı ve gizlilik (zorunlu)

- Çekirdek dış servise **ham telemetri veya ham graf** göndermez; yalnız **çıkarılmış,
  gerektiğinde redakte edilmiş** özellik/token gönderir (ör. `GraphFeatures`, token
  dizisi). Bu, `ARCHITECTURE-vNext.md` §7 "veri verir ve öneri döner" sınırını uygular.
- Kişisel/kiracı-hassas alanlar allowlist ile filtrelenir; `tenant_id` dış servise
  taşınmaz (veya opak bir korelasyon kimliğiyle değiştirilir).
- Dış servis yanıtı **veridir, komut değildir** — LLM çıktısı asla doğrudan aksiyon
  parametresine bağlanmaz; her zaman `aiassist.Gate` + `authz` üzerinden geçer.

### 5.5 Çekirdekten opsiyonel bağlama (env ile)

> **Not (durum):** Aşağıdaki çok-uçlu env şeması PLANDIR — henüz uygulanmadı. Mevcut
> implementasyon (`server/internal/aibrain`, `services/ai`) tek uç kullanır: `KUT_AI_URL`
> (+ opsiyonel `KUT_AI_KEY`/`KUT_AI_MODEL`). Bu bölüm ileriki ayrıştırma tasarımıdır.

```go
// Config, dış AI servislerini opsiyonel bağlar. Tüm alanlar boşsa LOCAL stub kullanılır.
type Config struct {
    SequenceURL string        // KUT_AI_SEQUENCE_URL (boş → LOCAL n-gram)
    GraphURL    string        // KUT_AI_GRAPH_URL     (boş → LOCAL metrik)
    LLMURL      string        // KUT_AI_LLM_URL       (boş → aiassist.LocalProvider)
    Timeout     time.Duration // KUT_AI_TIMEOUT_MS    (varsayılan 800ms)
}

// FromEnv, ortam değişkenlerinden Config kurar; hiçbiri set değilse LOCAL varsayılan.
func FromEnv() Config

// Build, Config'e göre bir Brain kurar: her uç için URL varsa HTTP istemcisi, yoksa
// LOCAL sağlayıcı. Kısmi yapılandırma desteklenir (ör. yalnız LLM dış, gerisi LOCAL).
func Build(cfg Config) *Brain
```

Kural: **env yoksa hiçbir davranış değişmez** — sistem tam olarak bugünkü deterministik
haliyle çalışır. Dış servis eklemek tamamen opt-in ve geri-alınabilirdir.

---

## 6. AI-SPM / Agentic-AI güvenliği (P5) — kısa değini

P5, KUT'un **kendi AI sistemlerini KORUMA** yeteneğidir (defansif, çekirdek prensibin
doğal uzantısı). P4'ün eklediği aynı telemetri/graf omurgasına oturur:

- **Envanter:** kuruluştaki LLM/MCP/RAG/ajan uç noktaları `entitygraph`'ta yeni düğüm
  türleri olarak modellenebilir (ör. `model`, `tool`, `prompt_source`) ve `Connected`/
  `Ran` benzeri kenarlarla ilişkilendirilir.
- **Prompt-injection / tool-abuse tespiti:** AI çağrı telemetrisi (girdi/araç-çağrısı
  dizileri) P4.1 sekans motoruna beslenir — anormal araç-çağrı dizisi = nadir geçiş.
- **Aynı gateway:** bir ajanın tetiklediği yüksek-etkili aksiyon da `authz.AI`
  talepçisi olarak `Gateway.Authorize`'dan geçer; agentic AI hiçbir ayrıcalık kazanmaz.
- **Servis:** `services/ai-security/` (dış), ama tespit sinyalleri yine `riskfusion`'a
  birer sinyal olarak girer. Ayrıntı ayrı P5 belgesine bırakılır.

---

## 7. Somut ilk adım — önerilen P4.1 (deterministik sekans nadirliği)

**Öneri: İlk uygulanacak parça = P4.1 Aşama 1 (Go n-gram/Markov `ScoreSequence`) +
`aibrain` iskeleti (`Provider`, `Brain` fail-open sarmalayıcı, `LocalProvider`).**

Gerekçe:

| Ölçüt | Neden P4.1 |
|---|---|
| **En yüksek değer** | Yeni/nadir davranış tespiti klasik imza/eşik tespitinin göremediği katmandır; süreç-ağacı verisi zaten `entitygraph`'ta (`ChildOf`, `Ran`) mevcut. |
| **En düşük risk** | Tamamen deterministik, bellek-içi, zero-dep; hiçbir dış servis, hiçbir yeni `go.mod` girişi gerekmez. Çekirdek duruşu korunur. |
| **CI-doğrulanabilir** | Sabit eğitim dizileri → sabit skor; golden-test + `CGO_ENABLED=0` derleme. Determinizm garanti. |
| **Dikişi kanıtlar** | `aibrain.Provider` + `Brain` fail-open sarmalayıcısı ilk kullanıcısını kazanır; sonraki tüm alt-fazlar (graph, LLM, dış servis) aynı dikişe takılır. |
| **Bağımsız** | `riskfusion`'a tek bir `Signal` ekler; mevcut açıklanabilirlik ve `Counterfactual` denetimi anında uygulanır. Geri-alınabilir (ağırlık 0 → etkisiz). |

Ölçülebilir "bitti" tanımı: `aibrain` paketi + `LocalProvider.ScoreSequence` +
`Brain` fail-open sarmalayıcı + golden-test'ler yeşil; `riskfusion`'a `seq` sinyali
opsiyonel eklenir ve AI yokken skor **birebir** değişmez.

---

## Ek — Paket dokunuş haritası

| Paket | P4'teki rolü | Değişiklik türü |
|---|---|---|
| `server/internal/aibrain` (**yeni**) | AI adaptör sınırı: `Provider`, `Brain`, `LocalProvider`, `SeqModel` | Yeni paket |
| `server/internal/riskfusion` | AI çıktısını birer `Signal` olarak alır | Değişiklik yok (mevcut API yeterli) |
| `server/internal/entitygraph` | Sekans/graf özelliklerinin kaynağı | Değişiklik yok (mevcut `Targets/Sources/Reachable`) |
| `server/internal/aiassist` | LLM/özet/triyaj LOCAL yolunun kaynağı (delege) | Değişiklik yok; `aibrain` tüketir |
| `server/internal/correlate` | Yüksek nadirlik → incident önceliği (besleme) | İleride opsiyonel kanca |
| `server/internal/casemgmt` | LLM özeti/önerilen varlık (besleme) | İleride opsiyonel kanca |
| `server/internal/authz` | Her AI önerisinin geçtiği tek sınır (`Requester=AI`) | Değişiklik yok |
| `services/ai-*` (**yeni, dış**) | Opsiyonel transformer/GNN/LLM servisleri | Ayrı birim; `go.mod`'a girmez |
