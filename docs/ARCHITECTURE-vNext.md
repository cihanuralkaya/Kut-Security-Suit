# KUT Security Suite — vNext Mimarisi (SOC / XDR / AI-native)

Bu belge, KUT'u bir EDR/MDM ajanından **uçtan uca AI-native SOC/XDR platformuna**
genişletmenin uygulanabilir yol haritasıdır. Greenfield bir tasarım değildir:
çekirdek katmanların çoğu **zaten paket tohumu olarak mevcuttur**; vNext bunları
tek bir güvenlik omurgası altında konsolide eder ve eksik katmanları ekler.

## 0. Değişmez ilke

> **Güvenlik sistemi AI'ı yönetir; AI güvenlik sistemini yönetmez.**

- **Çekirdek deterministiktir ve saf Go'dur** (sıfır yeni bağımlılık). Yüksek-etkili
  her karar bir insan onayına veya deterministik bir politikaya bağlanır.
- **AI/ML/LLM opsiyoneldir ve dışarıdadır.** Model çökse, erişilemez olsa veya
  yanlış karar verse bile enforcement durmaz ve blast-radius sınırı aşılamaz.
- Tüm yüksek-etkili aksiyonlar (Rules / SOAR / AI / Human) **tek bir kapıdan** geçer:
  `server/internal/authz` — Action Authorization Gateway.

## 1. Katmanlı mimari ve paket eşlemesi

```
 SOC COMMAND CENTER        Incidents · Cases · Hunting · Assets · Risk · Reports
        │                  [GAP: case/hunting yüzeyi + UI]
 AI SECURITY BRAIN         risk (fusion) · ueba · anomaly · model · threshold
        │                  [OPSİYONEL-DIŞ: transformer · GNN · LLM analyst]
 DETECTION / XDR ENGINE    detect · detectreg · detbits · ioc · mitre · dnstunnel · beacon
        │
 CORRELATION               correlate (detection→incident) · [GAP: entity/threat graph]
        │
 RESPONSE / SOAR           response · policypush · rollout · standdown(agent) · quarantine(agent)
        │
 ACTION AUTHZ GATEWAY      authz  ◄── §2, tek güvenlik sınırı
        │                  (scope · admin/RBAC · dual-control halen admin'de; buraya taşınacak)
 TELEMETRY FABRIC          connector · connectors · logingest · dedup · dlq · ingest
        │                  [GAP: OCSF/ECS ortak şema + SIEM data-lake ölçeği]
 KUT AGENTS                collector · inventory · netconn · dnsmon · fim · discovery · ...
```

Köşeli parantezli `GAP` / `OPSİYONEL-DIŞ` dışındaki her kutu **bugün var olan bir
Go paketidir**.

## 2. Action Authorization Gateway (omurga) — `server/internal/authz`

Bugün sağladığı deterministik kontroller:

| Kontrol | Kural |
|---|---|
| Blast-radius (insan) | Yumuşak-tavan; aşımda `NeedApproval` (açık onayla geçilir) |
| Blast-radius (otonom) | AI/SOAR/Rule için sert tavan (varsayılan 3) — onayla bile aşılamaz |
| Rate-limit | Talepçi başına dakikada N yüksek-etkili op |

**Konsolidasyon hedefi (P1):** bugün `admin.Service` içinde dağınık olan üç kontrol —
`guardScope` (Scope/ROE), `require` (RBAC), `wipeDualControl` (dört-göz) — Gateway'in
`Authorize(Request) Decision` çağrısı altında birleşecek. Böylece tek bir yerde:
kim · ne · nerede · risk · scope · onay · blast-radius · rate-limit.

## 3. Eksik çekirdek: Entity / Threat Graph — `server/internal/entitygraph` (yeni)

vNext'in en yüksek değerli eksik parçası. Deterministik, saf Go (bir graph için
harici DB gerekmez; başlangıçta ilişki tabloları + bellek-içi komşuluk yeterli).

- Düğümler: device · user · process · file · hash · domain · ip · cert
- Kenarlar: `ran`, `connected`, `resolved`, `logged_in`, `child_of`
- Sorgu: "bu hash başka nerede çalıştı?", "bu IP ile kim konuştu?" — korelasyon ve
  hunting bunun üstünde çalışır. GNN (opsiyonel-dış) daha sonra aynı grafı okur.

## 4. Ortak olay şeması (OCSF/ECS-uyumlu) — `telemetryschema` (yeni)

`connector`/`logingest` bugün olayları alıyor; eksik olan **tek normalize şema**.

```json
{ "ts": "...", "kind": "process_start|net_conn|auth|file",
  "host": {...}, "user": {...}, "process": {...}, "network": {...},
  "risk": {...}, "source": {...}, "tenant": "..." }
```

Windows Event/Sysmon, Linux audit, AD/Entra, firewall, DNS, cloud → bu şemaya map'lenir.

## 5. Yeni DB tabloları (kalıcılık)

`incidents`, `incident_alerts`, `cases`, `case_events` (immutable audit), `entities`,
`entity_edges`, `evidence_items` (evidence paketi zaten append-only + SHA-256 sağlıyor).
Hepsi `tenant_id` kapsamlı (mevcut çok-kiracılı desenle).

## 6. Faz planı ve bağımlılık dürüstlüğü

| Faz | İş | Nerede | Yeni bağımlılık |
|---|---|---|---|
| **P0 ✓** | Scope fail-closed · WIPE dual-control · authz gateway · script mutlak-yol | admin · authz · script | Hayır (bitti) |
| **P1** | Kontrolleri authz altında birleştir · script privilege reduction (Job Object / setuid drop) | authz · agent/script | Hayır |
| **P1** | Entity/Threat Graph · ortak olay şeması | entitygraph · telemetryschema | Hayır |
| **P2** | Incident/Case yönetimi + SOC yüzeyi · açıklanabilir risk-fusion | correlate · risk · adminapi | Hayır |
| **P2** | Detection-as-Code (versiyon · test · rollback) | detectreg | Hayır |
| **P3** | SIEM data-lake ölçeği · NDR sensor · ITDR (AD/Entra) | **yeni servisler** | **Evet — dış** |
| **P4** | Sequence/Transformer · GNN · LLM SOC analyst · risk fusion | `kut-ai-*` opsiyonel | **Evet — dış servis** |
| **P5** | AI-SPM / Agentic-AI güvenliği (LLM/MCP/RAG envanteri + prompt-injection tespiti) | `kut-ai-security` | **Evet — dış** |

## 7. Bağımlılık sınırı (kesin)

- **Çekirdekte (Go, sıfır-dep):** telemetry fabric, entity graph, detection, correlation,
  risk fusion (deterministik/ağırlıklı), response, **authz gateway**, SOC iş akışı.
- **Opsiyonel dış servis (yeni bağımlılık serbest):** transformer/GNN/LLM, vector DB,
  SIEM data-lake, NDR payload işleme. Bunlar çekirdeğe **veri verir ve öneri döner**;
  hiçbiri enforcement yolunda zorunlu değildir ve hepsi authz gateway'in altındadır.

```
kut-core · kut-agent · kut-ingest · kut-detection · kut-authz · kut-response · kut-soc
      └── OPSİYONEL: kut-ai-ml · kut-ai-graph · kut-ai-llm · kut-ai-security
```

AI katmanı düşerse çekirdek güvenlik çalışmaya devam eder — vNext'in temel dayanıklılık
garantisi budur.
