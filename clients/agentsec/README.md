# agentsec — KUT Agentic telemetry Go client

Hafif, **bağımlılıksız** (yalnız stdlib) Go client'ı: bir AI-agent runtime'ının
agent-davranış gözlemlerini KUT'a (`POST /api/agentsec/events`) bildirmesini sağlar.
KUT bunları Agent Causality Graph'a örer ve exfil zincirlerini
(`untrusted → credential → external`) tespit eder (`GET /api/agentsec/findings`).

Gözlemler **DATA**'dır; hiçbir yürütme tetiklemez.

## Kullanım
```go
import "kut.corp/suite/clients/agentsec"

c := agentsec.New("https://kut-c2:8445", token, 0)
b := agentsec.NewBatch().
    Node("assistant", agentsec.KindAgent, agentsec.TrustTrusted).
    Node("web", agentsec.KindContext, agentsec.TrustUntrusted).
    Node("api-key", agentsec.KindCredential, agentsec.TrustTrusted).
    Node("paste.evil", agentsec.KindExternal, agentsec.TrustTrusted).
    Read("assistant", "web").
    Read("assistant", "api-key").
    Write("assistant", "paste.evil")
if err := c.Report(ctx, b); err != nil { /* yeniden dene */ }
```

## Kenar türleri
`Read(agent, source)` · `Write(agent, sink)` · `Delegate(from, to)` · `Influence(from, to)`.
Güven: `TrustTrusted|TrustUntrusted|TrustTainted` (bilinmeyen sunucuda fail-safe Untrusted).

Boş yığın no-op'tur; non-2xx/ağ hatası `error` döner (KUT tarafı fail-open).
