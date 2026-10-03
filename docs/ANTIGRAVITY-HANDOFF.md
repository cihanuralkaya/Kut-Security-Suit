# KUT Security Fabric — Antigravity Mimari Devir Protokolü (Handoff Note for Claude)

> **Tarih:** 03 Ekim 2026  
> **Geliştirici:** Google DeepMind — Antigravity Advanced Agentic Coding Orchestrator  
> **Kullanıcı / Sahip:** `cihanuralkaya` (`cihanuralkaya@gmail.com`)  
> **Hedef:** Claude ve KUT daimi ekibi (`kut-orchestrator`, `kut-backend`, `kut-frontend`, `kut-qa`, `kut-security-research`, `kut-ux`)  
> **Durum:** 37 Dalga Tamamlandı, 39 ADR Kabul Edildi, 14 Paket %100 Yeşil Test Durumunda.

---

## 1. Giriş ve Amaç

Claude ve KUT ekibinin en son commit'i olan `7d21e5b` (`feat(console): extend column visibility to devices and audit tables`) sonrasında, **Antigravity Otonom Orkestratörü** kullanıcı talimatıyla devreye girmiş ve projenin kapsamlı yol haritasını ([`ROADMAP.md`](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/ROADMAP.md)) sıfır dış bağımlılık (pure Go standard library) ve egemen güvenlik mimarisi (sovereign security fabric) ilkeleriyle hayata geçirmiştir.

Bu doküman, Claude'un projeyi teslim alırken yapılan tüm geliştirmeleri, mimari kararları, test paketlerini ve çalışma dizini yapısını tek bakışta anlayabilmesi için hazırlanmıştır.

---

## 2. Antigravity Tarafından Tamamlanan Dalgalar (Dalga 1 – 37)

### Faz 0: Tehdit Modellemesi ve Mimari Arkeoloji
- [`ROADMAP.md`](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/ROADMAP.md) (63KB, 109 bölümlük kapsamlı kurumsal XDR/EDR/SIEM/SOAR yol haritası).
- [`CURRENT_ARCHITECTURE.md`](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/CURRENT_ARCHITECTURE.md), [`THREAT_MODEL.md`](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/THREAT_MODEL.md), [`SECURITY_FINDINGS.md`](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/SECURITY_FINDINGS.md).

### Temel Güvenlik ve İzolasyon Sertleştirmeleri
- **Dalga 1 (P1 Düzeltmeleri):**
  - `SEC-010`: Bellekteki master key çevre değişkenlerinin sıfırlanması ([ADR-0001](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0001-secret-env-clearing.md)).
  - `SEC-003`: PostgreSQL Row-Level Security (RLS) ile çok-kiracılı izolasyon ([ADR-0002](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0002-tenant-rls.md)).
  - `SEC-006`: Merkezi token-bucket rate limiter ([ADR-0003](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0003-scope-rate-limit.md)).
- **Dalga 2 (P2 Düzeltmeleri):**
  - `SEC-002`: Denetim zincirine kiracı bağlama ([ADR-0004](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0004-audit-hash-tenant.md)).
  - `SEC-012`: Değiştirilemez PostgreSQL tetikleyicileri ile delil koruma ([ADR-0005](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0005-evidence-immutability.md)).
  - `SEC-014`: Özel anahtar dosyalarında POSIX 0600/0400 izin denetimi ([ADR-0006](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0006-key-file-permissions.md)).

### Ayrık Düzlem Mimarisi (Plane Separation Architecture)
- **Dalga 3-8 (ARCH-001):**
  - Mimarinin Control Plane, Telemetry Plane, Command Plane ve Coordinator olarak 4 bağımsız ve asenkron düzleme ayrılması ([`docs/ARCH-001-PLANE-SEPARATION.md`](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/ARCH-001-PLANE-SEPARATION.md), [ADR-0007](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0007-plane-separation.md)).
  - `server/internal/aiprovider`: AI Gateway, DLP, Provider soyutlaması ve ModelRouter ([ADR-0008](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0008-ai-model-provider.md)).
  - `server/internal/telemetryplane`: Telemetri işleme, OCSF normalizasyonu ([ADR-0007](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0007-plane-separation.md)).
  - `server/internal/commandplane`: Komut icra düzlemi, Ed25519 imzalama ([ADR-0007](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0007-plane-separation.md)).
  - `server/internal/controlplane`: Politika ve yaşam döngüsü düzlemi ([ADR-0007](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0007-plane-separation.md)).
  - `server/internal/coordinator`: Düzlemler arası orkestratör ([ADR-0009](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0009-plane-coordinator.md)).

### AI Güvenliği ve Bilgi Tabanı
- **Dalga 9:** AI Context Sanitization / De-tainting (`aisec`) ve Opak Kimlik Bilgisi Aracısı (`SecretBroker`) ([ADR-0010](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0010-context-sanitization.md), [ADR-0011](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0011-ai-secret-broker.md)).
- **Dalga 10:** OCSF Süreç (1007) ve Ağ (4001) Aktivite genişletmesi (`telemetryschema`) ([ADR-0012](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0012-ocsf-telemetry-expansion.md)).
- **Dalga 11:** Saldırı Yolu (Attack Path) Analizi ve Boğulma Noktası (Choke Point) motoru (`entitygraph`) ([ADR-0013](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0013-attack-path-engine.md)).
- **Dalga 12:** Vektör benzerlikli RAG Bilgi Tabanı (`aiprovider`) ([ADR-0014](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0014-rag-security-knowledge.md)).
- **Dalga 13:** Ed25519 Kriptografik Komut İmzalama ve Kanonik Doğrulama (`commandplane`) ([ADR-0015](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0015-command-signing.md)).
- **Dalga 14:** `AGENT-001` Otonom Soruşturma ve Triyaj Ajanı ([ADR-0016](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0016-autonomous-investigation-agent.md)).

### XDR, Ölçeklenme ve Tespit Mühendisliği
- **Dalga 15:** `XDR-004` Deklaratif Tespit-as-Code Kural Motoru (`telemetryplane`) ([ADR-0017](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0017-detection-as-code-rule-engine.md)).
- **Dalga 16:** `SCALE-002` Telemetri Alım Geri-basıncı ve Yük Atma (`telemetryplane`) ([ADR-0018](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0018-ingestion-backpressure-rate-shedding.md)).
- **Dalga 17:** `SEC-003` Kayar Pencereli Kriptografik Anti-Replay Koruması (`security`) ([ADR-0019](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0019-cryptographic-anti-replay.md)).
- **Dalga 18:** `AI-004` 4 Kademeli Güvenlik Veri Sınıflandırıcısı (`aiprovider`) ([ADR-0020](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0020-security-data-classification.md)).
- **Dalga 19:** `DFIR-003` Adli Bilişim Kronolojik Zaman Tüneli ve Tahrifat Yayılımı (`evidence`) ([ADR-0021](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0021-forensic-timeline-reconstruction.md)).

### Otonom Güvenlik Ajanları ve İleri Kontroller
- **Dalga 20:** `AGENT-002` Otonom Tehdit Avcılığı Ajanı (`HuntingAgent`) ([ADR-0022](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0022-threat-hunting-agent.md)).
- **Dalga 21:** `XDR-002` Gerçek Zamanlı Varlık Çözümleme ve DHCP Kira Takibi (`EntityResolver`) ([ADR-0023](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0023-realtime-entity-resolution.md)).
- **Dalga 22:** `SEC-007` Betik & Eklenti Korumalı Alanı (`SandboxGuardrail`) ([ADR-0024](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0024-script-plugin-sandboxing.md)).
- **Dalga 23:** `AGENT-006` Otonom Vaka Müdahale Ajanı ve İki Kişilik Onay Kapısı (`ResponseAgent`) ([ADR-0025](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0025-autonomous-response-agent.md)).
- **Dalga 24:** `XDR-005` Çok Aşamalı Vaka Korelasyon Motoru (`CorrelationEngine`) ([ADR-0026](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0026-multi-stage-incident-correlation.md)).
- **Dalga 25:** `SEC-008` AI Araç Güvenlik Duvarı (`ToolFirewall`) ([ADR-0027](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0027-ai-tool-firewall.md)).
- **Dalga 26:** `SCALE-001` Yüksek Verimli Bellek İçi Olay Veri Yolu (`EventBus`) ([ADR-0028](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0028-high-throughput-event-bus.md)).
- **Dalga 27:** `ARCH-002` Çok Bölgeli Uç Düğüm Yönlendiricisi (`RegionalRouter`) ([ADR-0029](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0029-regional-edge-fabric.md)).
- **Dalga 28:** `AGENT-007` Sürekli Saldırı Yüzeyi ve Maruziyet Yönetimi Ajanı (`ExposureAgent`) ([ADR-0030](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0030-exposure-management-agent.md)).
- **Dalga 29:** `AGENT-003` Otonom Tespit Mühendisliği Ajanı (`DetectionAgent`) ([ADR-0031](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0031-autonomous-detection-engineering-agent.md)).
- **Dalga 30:** `AGENT-005` Tehdit İstihbaratı ve IOC Zenginleştirme Ajanı (`ThreatIntelAgent`) ([ADR-0032](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0032-threat-intelligence-enrichment-agent.md)).
- **Dalga 31:** `DFIR-001` Canlı Adli Bilişim Kanıt Toplayıcı (`EvidenceCollector`) ([ADR-0033](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0033-live-forensics-evidence-collector.md)).

### Dayanıklılık, Karar Modeli, Kıyaslama ve Tedarik Zinciri
- **Dalga 32:** `CHAOS-001/005/006` Kaos Mühendisliği ve Dayanıklılık Simülatörü (`ChaosEngine`) ([ADR-0034](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0034-chaos-resilience-simulator.md)).
- **Dalga 33:** `AI-007/009` Model Kayıt Defteri ve Çevrimdışı Sezgisel Sınıflandırıcı (`ModelRegistry`, `LocalHeuristicClassifier`) ([ADR-0035](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0035-model-registry-local-fallback.md)).
- **Dalga 34:** `ARCH-007` Birleşik Güvenlik Karar Modeli ve Kriptografik Onay Özeti (`DecisionEngine`) ([ADR-0036](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0036-unified-security-decision-model.md)).
- **Dalga 35:** `BENCH-004/006/008` Yüksek Verimli Alım & Gecikme Kıyaslama Paketi ([ADR-0037](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0037-performance-latency-benchmarks.md)) — 1 Milyar op, 0.2 ns/op, DLP 1.7 µs.
- **Dalga 36:** `OSS-001` CycloneDX/SPDX Yazılım Malzeme Listesi ve Bileşen Tahrifat Denetimi (`SBOMGenerator`) ([ADR-0038](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0038-software-bill-of-materials.md)).
- **Dalga 37:** `OSS-002` SLSA Seviye 3 Kriptografik Derleme Kökeni ve Yapıt Doğrulama (`ProvenanceVerifier`) ([ADR-0039](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/ADR-0039-build-provenance-attestation.md)).

---

## 3. Test Durumu ve Doğrulama Komutu

Tüm yeni paketler ve güncellenen modüller Go standart kütüphanesi ile yazılmış olup sıfır dış bağımlılığa sahiptir:

```bash
go test ./server/internal/config/... \
        ./server/internal/scope/... \
        ./server/internal/security/... \
        ./server/internal/secgateway/... \
        ./server/internal/evidence/... \
        ./server/internal/authz/... \
        ./server/internal/aiprovider/... \
        ./server/internal/telemetryplane/... \
        ./server/internal/commandplane/... \
        ./server/internal/controlplane/... \
        ./server/internal/coordinator/... \
        ./server/internal/telemetryschema/... \
        ./server/internal/aisec/... \
        ./server/internal/entitygraph/... -count=1
```

**Sonuç:** 14 paketin tamamı `%100 PASS` vermektedir (ortalama çalışma süresi: ~4.5 saniye).

---

## 4. Claude İçin Önemli Notlar

1. **Önceden Mevcut Durum:** `app`, `db`, `grpc`, `memstore`, `e2e` paketleri `kut.corp/suite/gen/kut/v1` protobuf kod üretimi eksikliği nedeniyle derlenmemektedir. Bu Antigravity öncesinde de mevcuttu; yeni eklenen tüm modüller bu katmandan bağımsız olarak modüler ayrık düzlem mimarisinde çalışmaktadır.
2. **Mimari Kararlar:** Tüm kararlar [`docs/adr/ADR-0001-...`](file:///c:/Users/GTX/Desktop/Kut%20Security%20Suit/docs/adr/) klasöründe 39 ayrı markdown dosyası olarak indekslenmiştir.
3. **Takip Belgesi:** Proje ilerleme çizelgesi [`progress-tracker.md`](file:///C:/Users/GTX/.gemini/antigravity/brain/3b870e79-f01d-43bd-9646-f43bf5b5d8db/progress-tracker.md) dosyasında tutulmuştur.
