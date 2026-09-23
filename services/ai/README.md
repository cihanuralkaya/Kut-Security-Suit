# KUT AI Service (iskelet / skeleton)

KUT için OPSİYONEL dış AI mikroservisi. `server/internal/aibrain/httpprovider.go`'nun
beklediği sözleşmeyi karşılar. Şu an **deterministik heuristik stub** (gerçek LLM yok) —
`handlers.py`'yi gerçek modelle değiştirin; sözleşme (uçlar + yanıt şekilleri) aynı kalır.

Ayrı bir workstream'dir: yalnız Python **stdlib** (bağımlılık/pip yok), kendi CI'si vardır
(`.github/workflows/ai-service.yml`). Go tarafını etkilemez.

## Uçlar (sözleşme)
- `POST /v1/summarize`   → `{text, confidence, source}`
- `POST /v1/triage`      → `{priority, likely_fp, next_steps, confidence, source}`
- `POST /v1/score-sequence` → `{score, rationale, source}`
- `POST /v1/score-graph` → `{score, rationale, source}`  (yalnız türetilmiş özellikler; ham graf ALMAZ)
- `POST /v1/explain-risk`→ `{text, source}`
- `GET  /health`         → `200 {status:"ok"}`

## Çalıştır (bağımlılıksız)
```
py app.py            # Windows
python3 app.py       # Linux/mac
# adres: KUT_AI_ADDR (vars. 127.0.0.1:8088)
```
c2'yi bu servise bağla:
```
KUT_AI_URL=http://127.0.0.1:8088 [KUT_AI_KEY=... KUT_AI_MODEL=...] ./c2 ...
```
Yapılandırılmazsa (KUT_AI_URL boş) c2 **fail-open**'dır: dış AI yok sayılır, deterministik
yol geçerlidir.

## Test
```
cd services/ai && python3 -m unittest   # (Windows: py -m unittest)
```

## Güvenlik notu
Servis salt-öneri üretir; hiçbir yürütme tetiklemez (enforcement KUT'ta `ActionRequest →
Gateway → Grant → GuardedExecutor` zincirinden geçer). Stub mantık fail-safe'dir; c2 her
hata/timeout'u "AI yok" gibi ele alır.
