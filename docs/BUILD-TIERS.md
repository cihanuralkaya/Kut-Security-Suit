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
| Depolama | yalnız PostgreSQL | + dayanıklı bus (NATS JetStream / Kafka) + analytics (ClickHouse) + object-store |
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
    analytics/                                (AnalyticsStore seam; nötr arayüz + ClickHouse impl)
      analytics.go         (build-tag'siz: AnalyticsStore arayüzü + tipler)
      clickhouse.go        //go:build enterprise   (ClickHouse impl; KUT_CLICKHOUSE_DSN)
    archive/                                  (Archive seam; nötr arayüz + S3/MinIO impl)
      archive.go           (build-tag'siz: Archive arayüzü Put/Get/List/Delete)
      s3.go                //go:build enterprise   (minio-go; KUT_S3_*)
    (sonra) secretsprov/  …                     (aynı impl+stub deseni)
server/cmd/
  c2/       (Lite tek binary — default; ince main → app.Run(nil))
  control/  main.go //go:build enterprise (app.Run(enterprise.Enable) — tam sunucu + dayanıklı bus) | main_stub.go //go:build !enterprise
  ingest/   main.go //go:build enterprise (veri-düzlemi tüketici: bus → normalize/detect → analytics+archive) | main_stub.go //go:build !enterprise
server/internal/
  app/      (PAYLAŞILAN sunucu bootstrap — app.Run(enterpriseHook); Lite c2 + Enterprise control ortak)
```

Seam'ler (genişletme noktaları): `eventbus.SetSink`, `cluster.NotifyBus`/`LeaseStore`,
`secrets.Provider`/`Chain`, `connector.Registry`. Bunlar Enterprise'ın **public kontratıdır** —
bilinçli dondurulur/versiyonlanır (contract-freeze).

## Module stratejisi (aşamalı)

`DurableLog` arayüzünün (Append/Replay/Close, contract-freeze) iki backend'i vardır ve
`KUT_BUS_BACKEND` ile seçilir:
- **`file` (varsayılan):** saf-Go dosya-tabanlı `DurableLog` (append-only JSONL, per-append fsync,
  çok-nesilli rotasyon; `bus/durable.go`). At-least-once "retention penceresi içinde"dir.
- **`jetstream`:** NATS JetStream (`bus/jetstream.go`). Go-native; sunucu SÜREÇ İÇİNE GÖMÜLEBİLİR
  (`KUT_NATS_URL` boşsa gömülü, doluysa harici küme). At-least-once (ACK bekler) + restart-replay.
  Gömülü olabildiği için testler dış servis olmadan koşar.
- **`kafka`:** Kafka-API / franz-go (`bus/kafka.go`). Zaten Kafka/Redpanda tabanlı güvenlik-veri-hattı
  olan enterprise'lar için "mevcut hatta takın" seçeneği. Harici broker gerekir (`KUT_KAFKA_URL`,
  `KUT_KAFKA_TOPIC`); tek partition (global sıralama), ProduceSync (ACK bekler). Gömülemez →
  CI'da ayrı **enterprise-kafka** job'ı Redpanda konteynerine karşı entegrasyon testi koşar
  (broker yoksa testler `t.Skip`).

Modül stratejisi:
- **Şimdi (A) — TEK MODULE:** İlk ağır dış istemci (NATS) geldi, ama nested-module'e terfi ETMEDİK.
  Neden: zero-dep DEĞİŞMEZİ Lite **binary**'si hakkındadır ve mekanik guard bunu binary'nin
  bağımlılık grafiğinde zorlar (`go list -deps ./server/cmd/c2 | grep nats-io → FAIL`); `jetstream.go`
  `//go:build enterprise` arkasında olduğu için Lite c2 NATS'ı DERLEMEZ. Nested-module yalnız kök
  `go.mod`'u kozmetik olarak temizler, ama bu alt-ağaç hem kökü import eder (`eventbus`) hem kök
  tarafından import edilir (`cmd/control`) → nested-module çift-yönlü yerel bağımlılık + kırılgan
  `go.work` gerektirir. Maliyet/fayda: erteliyoruz.
- **(B) — go.mod kirliliği gerçekten sorun olduğunda:** `server/internal/enterprise/`'i nested module
  (`go.mod`) + `go.work`'e terfi et → kök `go.mod` tertemiz (Lite grafiği NATS/kafka görmez). Bu adım
  Pattern 2'ye (ayrı overlay repo) geçişin provasıdır: alt-ağacı `git subtree split` ile private repoya
  çıkar, core'u `require kut.corp/suite vX.Y.Z` ile import et. Arayüzler sabit → geçiş taşıma, rewrite değil.

## Multi-tenant izolasyon (veri-düzlemi)

Kiracı (tenant) SUNUCU-TARAFI bağlanır, client'tan asla güvenilmez: ingest daemon'u `KUT_TENANT`
ile yapılandırılır ve tenant taşımayan olayların `tenant_id`'sini doldurur (araştırma ilkesi).
İzolasyon her tier'da `tenant_id` ile yapısaldır:
- **ClickHouse:** tablo `ORDER BY (tenant_id, occurred_at)`; sorgular tenant-kapsamlı
  (`CountBySeverity(tenant, …)` → `WHERE tenant_id = ?`), böylece bir kiracı diğerinin verisini göremez.
- **Arşiv (S3):** anahtarlar `events/{tenant}/{tarih}/{event_id}.json` — prefix izolasyonu.
- **Vaka deposu:** `casemgmt` zaten kiracı-kapsamlıdır (CaseAlertSink olay tenant'ını geçirir).

Altyapı-seviyesi sertleştirme (ClickHouse row-policy/quota, S3 prefix IAM, bus tenant ACL/partition
key) DAĞITIM konfigürasyonudur — kod bunları hazırlar (tenant her satır/anahtar/vakada), operatör
broker/DB tarafında zorlar.

## CI

CI iki tier'ı da derler/test eder ve **zero-dep guard** koşar:
`go list -deps ./server/cmd/c2 | grep -Ei 'kafka|clickhouse|minio|aws-sdk|redpanda' → varsa FAIL`.
Bu, prose'daki zero-dep değişmezini mekanik zorlar ve build-tag stub-drift'ini (imza sapması)
yakalar.

## Lisans

Çekirdek **Apache-2.0** kalır (relicense = fork riski — Elastic→OpenSearch, HashiCorp→OpenTofu).
İleride ticari kapatma gerekirse ticari lisans YALNIZ `server/internal/enterprise/` ve
`server/cmd/{control,ingest}` dizinlerine eklenir (dizin = lisans sınırı; GitLab `ee/` deseni).
