# CURRENT_ARCHITECTURE.md

## 1. Genel Bakış
KUT Security Suite, ajanlı (agent-based) bir uç nokta güvenlik (Endpoint Security) ve filo yönetim (MDM) platformudur. Proje; uç noktalarda çalışan bir Agent ve Watchdog süreçlerinden, merkezi yönetimi sağlayan bir Command & Control (C2) Server'dan ve SOC ekiplerine içgörü sağlayan dış bir AI Brain Service'inden oluşmaktadır.

## 2. Bileşenler (Components)

### 2.1 Server/C2 (Yönetim Sunucusu)
- **Sorumluluk**: Agent'ların güvenli kaydını yapmak (Enrollment), politika dağıtmak, olay loglarını toplamak, olayları korele ederek tehditleri (Incident/Case) saptamak ve yöneticiler için Admin HTTP API hizmeti sunmak.
- **Bağımlılıklar**: `pgx/v5` (PostgreSQL bağlantısı), `grpc`, `protobuf`. (Enterprise tier'da ek olarak `franz-go` (Kafka), `clickhouse-go`, `minio-go`).
- **Veri Akışı**: Agent'lardan mTLS ile alınan gRPC istekleri -> C2 Core / EventBus -> Korelasyon Motoru (Correlator) -> Veritabanı (PostgreSQL) -> (Opsiyonel) SIEM Syslog veya Webhook dışa aktarımı.
- **Güvenlik Sınırı**: Ajanlarla iletişim mTLS ve Certificate Pinning ile korunur. Veritabanındaki hassas alanlar Field-Level Encryption ve HMAC Blind Index ile at-rest korunur.
- **Hata Modu**: DB veya dış servislere (SIEM vb.) ulaşılamadığında veri kaybolmasını önlemek için Ingest Dead-Letter Queue (DLQ) mekanizması çalışır. Agent'lar tarafında Store-and-Forward ile tolerans sağlanır.
- **Ölçeklenme Sınırı**: Lite sürümü tek sunucu ve PostgreSQL performansına (connection limitlerine) dayanır. Yatay ölçekleme (Cluster Mode) için Postgres `LISTEN/NOTIFY` destekli fan-out mekanizması kullanılır. Yüksek hacimli analitik yükleri için `go build -tags enterprise` ile ClickHouse/Kafka gibi yatayda sınırsız ölçeklenebilen altyapılara bağlanabilir.

### 2.2 Agent (Uç Nokta Ajanı)
- **Sorumluluk**: Güvenlik politikalarını (Süreç kısıtlama, zaman bazlı kurallar, vb.) uygulamak, sistem gözlemleri yapmak (Ağ bağlantıları, FIM, USB Monitor, Anomali tespiti), sunucudan gelen anlık komutları (Karantina, Dosya Toplama) işletmek.
- **Bağımlılıklar**: Standart Go kütüphaneleri ve gRPC istemcisi. Dış (heavy) bağımlılığı yoktur.
- **Veri Akışı**: İşletim sistemi API'leri ve hook'larından alınan sinyaller Collector Buffer'da birikir -> Heartbeat döngüsünde `ReportEvents` gRPC çağrısıyla C2'ye "Store-and-Forward" mantığıyla yollanır.
- **Güvenlik Sınırı**: İşletim sistemi düzeyinde yetkili (SYSTEM/root) çalışır. İmzalı (Ed25519) OTA güncellemelerini ve İmzalı Script'leri doğrulamadan çalıştırmaz (Tamper Protection & Supply Chain Security).
- **Hata Modu**: Sunucu bağlantısı koptuğunda olayları yerel diske yazar, bağlantı sağlandığında C2'nin onayladığı "ACK" numarasına göre temizler (En-az-bir-kez teslimiyet).

### 2.3 Watchdog (Gözetmen)
- **Sorumluluk**: KUT Agent sürecini sürekli gözetlemek (Liveness), çöktüğünde güvenli geri-çekilme (Backoff) ile yeniden başlatmak ve OTA güncellemelerinde staging alanına inen yeni ikiliyi (binary) güvenle Swap etmek.
- **Hata Modu**: Watchdog çökerse, Agent onu liveness beacon takibi ile yeniden başlatır (Çift yönlü karşılıklı gözetim).

### 2.4 AI Brain Service (Yapay Zeka Servisi)
- **Sorumluluk**: SOC analistlerine olay özetleme (summarization), triyaj önerileri, agentic graph nedensellik analizi ve risk skorlaması sunan bir dış HTTP servisidir. 
- **Bağımlılıklar**: Python (Bağımlılıksız bir BaseHTTPRequestHandler iskelesi kullanır, gerçek üretimde LLM handler'ları bağlanır).
- **Veri Akışı**: C2'den JSON formatında veri alır, çıkarımlarını JSON olarak döner. Yürütme (execution) yapmaz, yalnızca tavsiye (triage) verir.

### 2.5 Agentsec Client
- **Sorumluluk**: Harici AI ajanlarının (LLM tabanlı otomasyonlar vb.) kendi iç işleyişlerini (okuma, yazma, yetki devri) KUT platformuna bildirmelerini sağlayan Go istemcisidir. `POST /api/agentsec/events` ucuna "Node" ve "Edge" formatında nedensellik (causality) grafiği yollar.

---

## 3. İletişim Akışı (Agent ↔ Server Communication)
Tüm Ajan-Sunucu iletişimi **gRPC** üzerinden, sertifika tabanlı **mTLS** (Mutual TLS) ile yapılır:
- **`EnrollmentService`**: Cihaz kurulumunda tek kullanımlık (One-Time) token ve CSR (Certificate Signing Request) ile çağrılır. Cihaza özel X.509 sertifikası üretilir.
- **`AgentService`**:
  - `Heartbeat`: Periyodik liveness sinyali. Sunucu saatini çıpa olarak döner (Saat manipülasyonuna karşı), Agent komut yürütme sonuçlarını (CommandResult) sunucuya raporlar.
  - `StreamPolicies`: Sunucu tarafında politika değiştiğinde, anlık olarak ajanlara itilen (Push) akıştır.
  - `ReportEvents`: Ajanın biriktirdiği logların Batch halinde gönderilmesi. Sunucu işlediği diziyi (Sequence) döner, ajan bu Sequence'e göre lokal buffer'ını boşaltır.
  - `CheckUpdate`: OTA paketlerinin (manifesto, imza) sorgulanması.
  - `UploadArtifact`: Sunucunun istediği adli kopyaların/dosyaların parçalı veya bütün halinde merkeze gönderilmesi.

---

## 4. Veritabanı Şeması (Database Schema)
- **Tür**: PostgreSQL (Opsiyonel olarak in-memory demo mode mevcuttur).
- **Temel Tablo Yapıları**:
  - `devices`, `enrollment_tokens`, `agent_certificates`: Cihaz kimlik ve PKI (Public Key Infrastructure) yaşam döngüsü.
  - `policies`, `policy_rules`, `device_policies`: Rol, zaman, ağ ve süreç kısıtlama kuralları.
  - `event_logs`: Zamana göre PostgreSQL Partitioning (Range tabanlı) uygulanmış ana log tablosudur.
  - `device_commands`: Yöneticinin verdiği anlık komutların (Lock, Wipe, Quarantine) kuyruğu.
  - `admins`, `audit_log`: Rol Bazlı Erişim Kontrolü (RBAC) ve manipüle edilemeyen Hash zincirli (Append-Only) denetim kayıtları.
  - `incidents`, `cases`: Alarm fırtınası bastırma (Correlation) sonucu gruplanan vakalar.

---

## 5. Güvenlik, Kimlik Doğrulama ve Yetkilendirme
- **Agent Kimlik Doğrulaması (Authentication)**: Sadece mTLS. Cihaz kimliği, bağlantı sırasında kullanılan sertifikanın CN (Common Name) bilgisinden alınır, payload'a güvenilmez. C2 Sunucusu için de SPKI Pinning uygulanır.
- **Admin Kimlik Doğrulaması**: UI/API için JWT. Çok Faktörlü Doğrulama (TOTP/MFA) zorlanabilir.
- **Yetkilendirme (Authorization)**: RBAC (VIEWER, OPERATOR, ADMIN). Kritik işlemler için (örn. Tüm cihazı WIPE etme) "Dual-Control / Dört Göz" ilkesi (Farklı iki ADMIN onayı) gereklidir.
- **Sırlar (Secrets Management)**: Master Key üzerinden (HMAC/HKDF ile) türetilen mantıksal alt anahtarlar kullanılır (Field Encryption, Session Token, Blind Index). Key Rotation desteklenir, yeni anahtar ile şifreleme yapılırken eski anahtarlar okuma halkasında (Ring) tutulur.

---

## 6. Yapılandırma ve Dağıtım (Configuration & Deployment)
- **Yapılandırma**: Tüm bileşenler `env` değişkenleriyle (Twelve-Factor App) ayarlanır. Örn: `KUT_DATABASE_URL`, `KUT_MASTER_KEY`, `KUT_AGENT_ADDR`.
- **Dağıtım Katmanı**:
  - **LITE Mod**: Tek binary C2, standart PostgreSQL. Go toolchain'i `go build` ile dış bağımlılıksız (zero-dep) üretilir.
  - **ENTERPRISE Mod**: `//go:build enterprise` koşulu ile derlenerek Kafka, ClickHouse, S3 (MinIO) sürücüleri aktif edilir ve yüksek hacimli veri hatlarına veri akışı sağlanır.
- **CI/CD**: GitHub Actions üzerinde gofmt, vet, yarış denetimi (race detector), güvenlik analizi (gosec, govulncheck, gitleaks) ve uçtan uca PostgreSQL tabanlı smoke testler uygulanır. SBOM (CycloneDX) üretilir.

---

## 7. Bağımlılık Grafiği (Dependency Graph)
```mermaid
flowchart TD
    subgraph Endpoint_Node [Uç Nokta / Agent (Go)]
        Watchdog(Watchdog)
        Agent(KUT Agent)
        Watchdog <-->|Karşılıklı Liveness Gözetimi| Agent
    end

    subgraph C2_Node [Yönetim Sunucusu / C2 (Go)]
        GRPC(gRPC Agent Svc)
        HTTP(Admin HTTP API)
        Core(Core Engine / Correlator / Pipeline)
        GRPC --> Core
        HTTP --> Core
    end

    subgraph External_Services [Dış Sistemler / Altyapı]
        AI(AI Brain Svc - Python)
        DB[(PostgreSQL)]
        SIEM(SIEM / Webhook / Kafka / S3)
    end

    Agent -- mTLS (Heartbeat, ReportEvents) --> GRPC
    Core --> DB
    Core -- JSON/CEF --> SIEM
    Core -- JSON HTTP --> AI
    HTTP -- JWT --> Admin_User(SOC Analisti / Admin)
```
