# ADR-0031: Autonomous Detection Engineering Agent (AGENT-003)

## Durum
Kabul Edildi

## Bağlam
Yeni ortaya çıkan tehdit taktikleri veya av hipotezleri (threat hunting findings) karşısında manuel kural yazma süreci günleri bulabilmektedir. Platformun, hipotezlerden ve telemetri sinyallerinden deklaratif tespit kuralları (Detection-as-Code) türeten ve bunları otomatik MITRE ATT&CK taksonomisi ve güvenilirlik puanıyla doğrulayan otonom bir Tespit Mühendisliği Ajanına ihtiyacı vardır.

## Karar
`server/internal/aiprovider` paketi altında `DetectionAgent` devreye alındı:
1. **Kural Taslağı Türetme (`DraftRuleFromHypothesis`)**:
   - `HuntHypothesis` ve örnek sinyalleri (`sampleSignals`) analiz ederek deklaratif `DetectionProposal` üretir.
   - Kategori (`process`, `network`, `file`), regex/desen, MITRE taktik ve tekniği ile gerekçe (`Rationale`) tanımlar.
2. **Kural Doğrulama & Guardrail (`ValidateProposal`)**:
   - Regex desenlerinin sözdizimsel geçerliliğini doğrular.
   - MITRE taktik formatını (`TA0001` vb.) ve teknik kodlarını (`T1059` vb.) denetler.
   - Ciddiyet (`low`, `medium`, `high`, `critical`) ve güven skoru (Confidence 0.0 - 1.0) kontrolü yapar; geçersiz kurallar tespit motoruna verilmeden önce elenir.

## Sonuçlar
- Tehdit avcılığından tespit kuralına dönüşüm döngüsü dakikalara indirildi ve tespit kalitesi otomatik guardrailler ile güvenceye alındı.
