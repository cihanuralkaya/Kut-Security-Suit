# Milestone A / PR-01 — Freeze-sonrası Executor & Privileged-Mutation Delta Audit (v1.1, READ-ONLY)

**Durum:** READ-ONLY denetim baseline. **Hiçbir canlı yol değiştirilmedi.** Migration bu audit gate'i kapandıktan sonra adapter-first başlar.
**Baseline:** `docs/CONTRACTS.md` v3.2.1 (FREEZE) ↔ mevcut kod (yerel repo; web-indeksi kaynak DEĞİL).
**v1→v1.1:** Executor sınırı yalnız "command üreten" yüzey değil; **güvenlik sonucu doğuran tüm privileged side-effect'ler**. Eklendi: command-dışı mutasyon satırları, **Side-effect class** sütunu + `PrivilegedMutation` kavramı, ApproveWipe approval-concurrency, Erase partial-failure, desired≠effective quarantine, test/build-tag/helper bypass taraması, risk yeniden-sıralaması (G-02 kök-neden > G-01 semptom).

**Hedef zincir:** `ActionRequest → Gateway → (Approval→Finalize) → Grant → GuardedExecutor → { CommandEnvelope | PrivilegedMutation }`.

---

## 1. Side-effect sınıfları (yeni)
| Sınıf | Örnek | Grant+ExecutionIntent gerek? |
|---|---|---|
| `DEVICE_COMMAND` | EnqueueCommand* (WIPE/QUARANTINE/LOCK/RESTART/COLLECT_*) | **Evet** |
| `SECURITY_STATE_MUTATION` | SetDeviceStatus(QUARANTINED), SavePendingWipe/DeletePendingWipe | **Evet** |
| `DESTRUCTIVE_SERVER_MUTATION` | EraseDeviceData | **Evet** (fail-closed + journal) |
| `IDENTITY_CREDENTIAL_MUTATION` | RevokeDeviceCerts, RevokeEnrollmentToken | **Evet** |
| `POLICY_MUTATION` | AssignPolicy (+ dolaylı agent push) | **Evet** |
| `METADATA_ONLY` | SetDeviceTags, SetEventAck | Hayır (yine RBAC+tenant+audit) |

**`PrivilegedMutation` kavramı:** her DB yazısı GuardedExecutor'a girmez; ama güvenlik sonucu doğuran server-side mutasyonlar (Erase/cert-revoke/policy/security-state) "command değil" diye authorization sınırının DIŞINDA kalmaz. GuardedExecutor iki uç sunar: `CommandEnvelope` (cihaz) ve `PrivilegedMutation` (server state).

## 2. Call-path × delta tablosu
Sütunlar: **Side-effect class** · **Mevcut guard** · **Bypass?** · **Tenant** · **Approval** · **Grant** · **Raw-store** · **Test** · **Risk**

| # | Call-path | Sınıf | Mevcut guard | Bypass? | Tenant | Approval | Grant | Raw-store | Test | Risk |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | WipeDevice→EnqueueCommand(WIPE) | DEVICE_COMMAND | require(Admin)+guardScope+gateAction | kısmi | scopeTenant | dual-ON | yok | evet | var | Yüksek |
| 2 | RequestWipe→SavePendingWipe | SECURITY_STATE | require(Admin)+guardScope | — | scopeTenant | başlatır | yok | evet | var | Orta |
| 3 | ApproveWipe→EnqueueCommand(WIPE)+DeletePendingWipe | DEVICE_COMMAND | require(Admin)+dört-göz+guardScope | **concurrency** (aşağı) | scopeTenant | tamamlar | yok | evet | var | Yüksek |
| 4 | Quarantine/Lock/Restart→command()→EnqueueCommand | DEVICE_COMMAND | require(Op)+guardScope(+gateAction lock/restart) | kısmi (quarantine tekil gate yok) | scopeTenant | yok | yok | evet | var | Orta |
| 5 | Release/CollectDiagnostics→command() | DEVICE_COMMAND (düşük) | require(Op), scope MUAF | düşük | scopeTenant | yok | yok | evet | var | Düşük |
| 6 | CollectFile→EnqueueCommandParams | DEVICE_COMMAND | require(Op), guardScope YOK | kısmi | scopeTenant | yok | yok | evet | kısmi | Orta |
| 7 | command() reflectStatus→SetDeviceStatus | SECURITY_STATE | (command ile) best-effort | **desired≠effective** (aşağı) | scopeTenant | yok | yok | evet | var | Orta |
| 8 | EraseDevice→EraseDeviceData | DESTRUCTIVE_SERVER | require(Admin), guardScope/gateway YOK | **kısmi + partial-failure** (aşağı) | **yok** | yok | yok | evet | kısmi | Yüksek |
| 9 | RevokeDeviceCerts | IDENTITY_CREDENTIAL | require(Admin), guardScope YOK | kısmi | yok | yok | yok | evet | kısmi | Yüksek |
| 10 | AssignPolicy→AssignPolicy **+ pub.Publish(deviceID)** | POLICY_MUTATION (**dolaylı executor**) | require(Admin), guardScope YOK; bulk gateway | **kısmi** | **yok** | yok | yok | evet | var(bulk) | Yüksek |
| 11 | SetDeviceTags→SetDeviceTags | METADATA_ONLY | require(Op) | düşük | yok | yok | yok | evet | var | Düşük |
| 12 | SetEventAck→SetEventAck | METADATA_ONLY | require(Op/Viewer) | düşük | kısmi | yok | yok | evet | var | Düşük |
| 13 | **AutoQuarantine→EnqueueCommand(QUARANTINE)+SetDeviceStatus** | DEVICE_COMMAND+SECURITY_STATE | **HİÇBİRİ** (systemActor) | **🔴 TAM BYPASS** | yok | yok | yok | evet | dolaylı | Kritik |
| 14 | RevokeEnrollmentToken | IDENTITY_CREDENTIAL | require(Admin) | kısmi | scopeTenant | yok | yok | evet | var | Orta |
| 15 | adminapi bulk→per-device admin.Service | mixed | gateway blast/rate + per-call guardScope | kısmi | scopeTenant | yok | yok | evet | var | Orta |

## 3. Derinleştirilmiş bulgular (v1.1 istekleri)

**F-A — AssignPolicy dolaylı executor edge (satır 10).** `AssignPolicy` DB yazısından sonra `s.pub.Publish(deviceID)` ile agent'ın açık politika akışını **uyandırır** → agent yeni politikayı çeker/uygular. Yani "yalnız DB alanı" değil; **cihaz side-effect'i olan POLICY_MUTATION**. Authorization sınırı dışında kalmamalı; grant+intent gerektirir.

**F-B — ApproveWipe approval concurrency (satır 3).** Mevcut akış: `GetPendingWipe` → requester≠approver kontrol → `guardScope` → `EnqueueCommand(WIPE)` → `DeletePendingWipe`. **Yarış:** aynı pending-wipe'a iki eşzamanlı ApproveWipe → ikisi de GetPendingWipe'ı okuyup ikisi de EnqueueCommand yapabilir (DeletePendingWipe idempotent ama komut **iki kez** kuyruğa girebilir). Freeze bunu Approval **atomik consume** (CONSUMED tek kez) + Grant tek-kullanımla çözer (B4/INV-040, §4). **Migration'da ApproveWipe → FinalizeAuthorization'a taşınmalı.**

**F-C — EraseDevice partial-failure (satır 8).** `EraseDeviceData` tek çağrıda birden çok yıkıcı side-effect yapar (events+commands sil + cert revoke; sayaçları döner). Non-transactional ise: **veri silindi ama cert-revoke başarısız** → `err` döner, ErasureReport dönmez, ama veri zaten gitmiştir → tutarsız/kanıtlanamaz sonuç. Freeze gereği (KUT-SEC-004/007, INV-027): destructive fail-closed + durable ExecutionIntent + partial-failure için `EXECUTION_UNKNOWN`/reconciliation. **DB-impl atomikliği (tek TX) veya intent-tabanlı reconciliation gerekir.**

**F-D — desired ≠ effective quarantine (satır 7/13).** `SetDeviceStatus(QUARANTINED)` yalnız **DB durum alanı** (desired); gerçek izolasyon ayrı `QUARANTINE` komutunun agent'ta uygulanmasıyla (effective) olur. İkisi ayrı → SOC'ta cihaz **gerçekte izole olmadan "quarantined" görünebilir**. Freeze quarantine lifecycle'ı (§8: APPLYING→ACTIVE, doğrulanmış effective state) tam bunu ayırır. **Migration'da desired-state, effective-state doğrulanana dek "ACTIVE" gösterilmemeli.**

**F-E — test/build-tag/helper bypass taraması.** `_test.go`, memstore, `*_windows.go`, tools/, cmd/ tarandı. **Production'da yeni bypass YOK:** `SetDeviceTags` çağrıları `admin.Service` üzerinden (RBAC'li). memstore `_test.go`'ları raw store'u **doğrudan** çağırıyor (store unit-testi — meşru) **ama bu G-02'yi kanıtlıyor: raw mutation yüzeyi export edilmiş ve production paketlerinden erişilebilir.** CLI/tools/agent/windows'ta raw-Store mutasyon bypass'ı yok.

## 4. Yapısal boşluklar — YENİDEN sıralanmış risk
```text
G-02  CRITICAL  Raw privileged executor/mutation yüzeyi bypass-edilebilir (KÖK NEDEN)
G-01  CRITICAL  AutoQuarantine = G-02'nin somut exploit yolu (semptom)
G-03  HIGH      Erase destructive authorization/journal + partial-failure boşluğu (F-C)
G-05  HIGH      Tenant binding eksik (Erase/Assign/Cert tenant taşımıyor)
G-04  HIGH      Collect/Policy(+push)/Quarantine tutarsız authorization (F-A)
G-08  HIGH      ApproveWipe approval-consume concurrency (F-B) [YENİ]
G-09  HIGH      desired≠effective quarantine state (F-D) [YENİ]
G-06  EXPECTED  Frozen contracts henüz canlı yola bağlı değil
G-07  MEDIUM    Yetersiz doğrudan negatif/concurrency testi
```
**Gerekçe:** G-02 (açık raw yüzey) bypass SINIFINI mümkün kılar; G-01 onun bir örneğidir. AutoQuarantine'ı düzeltip raw Store'u açık bırakırsak yarın başka background worker aynı bypass'ı yeniden yaratır → önce kök-neden (bariyer), sonra semptom.

## 5. Adapter-first migration dilimleri (güncellenmiş; her dilim invariant-yeşil olmadan sonrakine GEÇME)
- **PR-01** ActionRequest v2 + Gateway.Authorize→AuthorizationDecision köprüsü (seccontract tiplerini canlı `authz`'a bağla; davranış-koruyan paralel yol).
- **PR-02 (revize):** ÖNCE `PrivilegedMutation`/executor arayüzlerini **internal/unexported** yapacak adapter tasarımı + **compile-time bypass testleri** (raw mutation üretim-paketinden çağrılamaz). Bu PR'da henüz production executor'a bağlanmaz — yalnız bariyer + testler (G-02 kök-neden).
- **PR-03** AutoQuarantine → ActionRequest(autoresponder) → Gateway → Grant → GuardedExecutor (G-01 kapanır; izole, en yüksek değer).
- **PR-04** WIPE + **ApproveWipe → FinalizeAuthorization** (G-08) + destructive ExecutionIntent (#1-3).
- **PR-05** command() (Quarantine/Lock/Restart) + CollectFile + **AssignPolicy(+push)** tek Gateway (G-04/F-A).
- **PR-06** EraseDevice + RevokeDeviceCerts fail-closed + durable journal + partial-failure reconciliation (G-03/F-C).
- **PR-07** Tenant-bound her yol + missing→DENY (G-05); desired≠effective quarantine ayrımı (G-09/F-D).
- **PR-08** bypass/invariant/fuzz/concurrency test süiti (INV-001..052 canlı yollar üzerinde).

## 6. Not — repo görünürlüğü
Denetim **yerel repo** üzerinden (tek otoriter kaynak). Web-arama indeksi güvenilir kaynak ağacı döndürmüyor; web'den tahmin yürütülmedi. Commit/PR/CI-seviyesi takip için GitHub entegrasyonu opsiyonel bağlanabilir.

## 7. Gate durumu
Bu doküman salt-okunur baseline'dır; sonraki PR'larda "bu bypass gerçekten kapandı mı?" diff üzerinden bu tabloya karşı ölçülür. **v1.1'de yeni KRİTİK yol çıkmadı** (yeni bulgular F-A..F-E mevcut risk sınıflarına eklendi). Audit gate kapanınca PR-01 başlar.
