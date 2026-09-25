# Build Tiers — KUT Lite ve KUT Enterprise

KUT tek bir kod tabanından iki dağıtım katmanı üretir. Ayrı repo/fork YOKTUR — fark yalnız
**derleme etiketi (`//go:build enterprise`) + çalışma modu (`KUT_MODE`)**. Bu, GitLab CE/EE
(`ee/` dizini) ve HashiCorp (build-tag) desenidir ve reponun mevcut `//go:build onnx`
opsiyonel-backend emsalini (bkz. `docs/ONNX.md`) altyapıya uygular.

## Katmanlar

| | KUT Lite (varsayılan) | KUT Enterprise |
|---|---|---|
| Derleme | `go build ./...` | `go build -tags enterprise ./...` |
| Binary | `cmd/c2` (tek binary) | `cmd/control` + `cmd/ingest` |
| Depolama | yalnız PostgreSQL | + dayanıklı bus (Kafka/Redpanda) + analytics (ClickHouse) + object-store |
| Çalışma modu | `KUT_MODE` boş/`lite` | `KUT_MODE=scale` |
| Dış bağımlılık | **sıfır ağır dep** (pgx/grpc taban) | ağır infra istemcileri (yalnız enterprise tag'i arkasında) |

## Değişmez kural (zero-dep korunur)

> Her AĞIR dış import (Kafka/ClickHouse/object-store/KMS/cloud-SDK/scanner) YALNIZ bir
> `//go:build enterprise` dosyasında yer alır. Çekirdek ona **yalnız arayüz** üzerinden
> dokunur; her enterprise dosyanın imza-eşli bir `//go:build !enterprise` **saf-Go stub**'ı
> vardır. Böylece `go build ./...` (Lite) hiçbir ağır dep derlemez.

**Bağımlılık yönü tek taraflı:** `enterprise → core`. Çekirdek paketler
`internal/enterprise/...`'i **asla** import etmez; wiring ters yönde akar (enterprise
`Enable()` → `eventbus.SetSink`, `connector.Registry.Register`, `secrets.Provider` …).

## Dizin düzeni

```
server/internal/
  eventbus/ cluster/ secrets/ connector/   (core — arayüzler/seam'ler burada)
  enterprise/                               (EE-only; enterprise → core)
    enterprise.go        //go:build enterprise   (Enable + Edition="Enterprise")
    enterprise_stub.go   //go:build !enterprise  (Enable→ErrNotCompiled, Edition="Lite")
    bus/  bus.go (enterprise, durable-bus seam) | bus_stub.go (!enterprise)
    (sonra) analytics/  blob/  secretsprov/  …   (aynı impl+stub deseni)
server/cmd/
  c2/       (Lite tek binary — default)
  control/  main.go //go:build enterprise | main_stub.go //go:build !enterprise
  ingest/   main.go //go:build enterprise | main_stub.go //go:build !enterprise
```

Seam'ler (genişletme noktaları): `eventbus.SetSink`, `cluster.NotifyBus`/`LeaseStore`,
`secrets.Provider`/`Chain`, `connector.Registry`. Bunlar Enterprise'ın **public kontratıdır** —
bilinçli dondurulur/versiyonlanır (contract-freeze).

## Module stratejisi (aşamalı)

- **Şimdi (A):** tek module + build-tag. Enterprise henüz ağır dep EKLEMEDİ — dayanıklı bus'ın
  ilk fazı **saf-Go dosya-tabanlı `DurableLog`**'tur (append-only JSONL, per-append fsync,
  çok-nesilli rotasyon; `server/internal/enterprise/bus/durable.go`). At-least-once garantisi
  "retention penceresi içinde"dir: pencere aşılırsa yalnız en eski nesil düşer.
- **İlk gerçek ağır client geldiğinde (B):** Redpanda/Kafka producer'ı **aynı `DurableLog`
  arayüzünü** (contract-freeze) uygular; o an `server/internal/enterprise/`'i **nested module**
  (`server/internal/enterprise/go.mod`) + `go.work`'e terfi et → kök `go.mod` tertemiz kalır
  (Lite grafiği kafka/clickhouse görmez). Bu adım, ileride Pattern 2'ye (ayrı overlay repo)
  geçişin provasıdır: alt-ağacı `git subtree split` ile private repoya çıkar, core'u
  `require kut.corp/suite vX.Y.Z` ile import et. Arayüzler sabit kalır → geçiş taşıma, rewrite değil.

## CI

CI iki tier'ı da derler/test eder ve **zero-dep guard** koşar:
`go list -deps ./server/cmd/c2 | grep -Ei 'kafka|clickhouse|minio|aws-sdk|redpanda' → varsa FAIL`.
Bu, prose'daki zero-dep değişmezini mekanik zorlar ve build-tag stub-drift'ini (imza sapması)
yakalar.

## Lisans

Çekirdek **Apache-2.0** kalır (relicense = fork riski — Elastic→OpenSearch, HashiCorp→OpenTofu).
İleride ticari kapatma gerekirse ticari lisans YALNIZ `server/internal/enterprise/` ve
`server/cmd/{control,ingest}` dizinlerine eklenir (dizin = lisans sınırı; GitLab `ee/` deseni).
