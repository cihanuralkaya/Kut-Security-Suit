# Remediation Verification — KUT Doğrulama Motoru

KUT, DETECTION → RESPONSE → **VERIFICATION** halkasını kapatır: bir bulgu "çözüldü"
olarak kapatılmadan önce, **gerçekten düzelip düzelmediği** taze telemetriye karşı yeniden
ölçülür. "resolved işaretlendi" ≠ "düzeldi"; motor bunu ölçer.

Paket: `server/internal/verify` (saf-Go, çekirdek-içi, zero-dep — Lite guard uyumlu).

## Neden çekirdek-içi ve fail-closed?

Doğrulama, vaka-kapanışını gate'ler ve denetim-izi DOĞRULUĞU üretir → **fail-closed**
olmalı: değerlendirilemeyen bir check ASLA `VERIFIED` vermez. Bu yüzden mevcut fail-open
AI seam'inin (`aibrain` → `services/ai`, sağlayıcı yoksa "sonuç yok, devam") arkasına
KONMAZ; oraya konsa güvenlik özelliği tersine dönerdi. (İleride **predictive / what-if**
risk-azalması ayrı, advisory, fail-open bir Python kuzeni olabilir — doğrulama karar
yolunda DEĞİL.)

## Sonuçlar (Outcome)

- `PENDING` — pencere (WindowEnd) henüz dolmadı.
- `VERIFIED` — kaynak sinyal taze pencerede doğrulanabilir biçimde kayboldu.
- `REGRESSED` — sinyal hâlâ tetikliyor (düzelme yok).
- `INCONCLUSIVE` — pencerede telemetri yok → karar verilemez (fail-closed: VERIFIED değil).

## Nasıl çalışır (DetectionVerifier)

`adminread.ReplayDetections`'ın TERSİ: replay "bu kural geçmişte kaç olayı yakalardı?"
der; doğrulama "kaynak kural taze (aksiyon-sonrası) pencerede ARTIK tetikliyor mu?" der ve
**sıfır eşleşme** bekler. `RuleRunner` arayüzü (`Evaluate(model.Event) []detect.Detection`)
mevcut `*detect.Engine` tarafından doğrudan karşılanır (import döngüsü yok).

## Doğrulama türleri (Kind)

- **`detection`** (varsayılan) — kaynak tespit kuralını taze pencerede yeniden koşturur
  (`DetectionVerifier`, yukarıda). Sinyal = olaylar.
- **`device_status`** — cihazın GÜNCEL efektif durumunu beklenen duruma (`expected`, ör.
  `QUARANTINED`/`ACTIVE`) karşı ölçer (`EvaluateDeviceStatus`). Sinyal = cihazın DURUMu
  (olay değil): `DeviceDetail` ile okunur; eşleşme → VERIFIED, aksi → REGRESSED, durum
  bilinmiyor → INCONCLUSIVE (fail-closed). **desired≠effective boşluğunu kapatır:** bir
  karantina komutu verildikten sonra cihazın gerçekten `QUARANTINED` efektif duruma
  ulaştığını (yalnız `QUARANTINE_PENDING`'de takılı kalmadığını) doğrular.

## Gerçekleşen (ölçülen) risk azalması

- Açılışta `Baseline = risk.Score(Factors)` (bulgunun risk girdileri).
- `VERIFIED`'de kalan risk = sinyal-bağımlı faktörler asgariye indirilmiş skor (Confidence
  küçük epsilon — `risk.Score` 0'ı "tam güven" sayar —, Exploitability 0); yapısal risk
  (varlık kritikliği + maruziyet) dürüstçe kalır.
- `RiskReduced() = Baseline − Residual` (0 tabanlı): VERIFIED'de pozitif, REGRESSED/
  INCONCLUSIVE'de 0; kalan asla Baseline'ı aşmaz.

## API (kiracı SUNUCU-TARAFI; bkz. docs/MULTI-TENANCY.md)

- `POST /api/verify/open` (OPERATOR+) — `{finding_ref, device_id, rule_id, kind, expected, factors, window_secs}`; kiracıya bağlı check açar (`expected` yalnız `kind=device_status` için).
- `POST /api/verify/{id}/run` (OPERATOR+) — cihazın açılış-sonrası taze olaylarını (QueryEvents, kiracı-kapsamlı) çekip yeniden değerlendirir, çözer ve denetim izine yazar.
- `GET /api/verify` (VIEWER+) — çağıranın kiracısının check'leri; platform admini (boş kiracı) tümünü.

## Vaka bağlama

`casemgmt.AttachVerification` ekleme türü + `"verify"` timeline olayı ile bir doğrulama
sonucu vakanın değişmez zaman çizelgesine ve `Verifications` listesine bağlanır.

### Vaka-kapanışı doğrulama gate'i (opt-in)

`KUT_VERIFY_REQUIRE_ON_CLOSE=1` ile (default KAPALI, non-breaking) bir vaka **CONTAINED→
CLOSED** geçişi yaparken vakaya bağlı `Verifications` referanslarından en az birinin
`VERIFIED` sonuçlu bir check'e çözülmesi ZORUNLU olur; yoksa geçiş **409** ile reddedilir
(fail-closed). Gate yalnızca CONTAINED kaynağını hedefler — OPEN→CLOSED gibi diğer geçişler
etkilenmez. Böylece "resolved işaretlendi" ≠ "düzeldi" boşluğu vaka-kapanışında kapanır:
kapatma, ölçülmüş bir düzelme kanıtı ister. Kiracı kapsamı SUNUCU-TARAFI çözülür (platform
admini → `GetAny`; kiracı-bağlı admin → `Get(tenant, ...)`).

## Otomatik mod (opsiyonel, default KAPALI)

`KUT_VERIFY_AUTO=1` (+ otomatik-müdahale) ile: `response.AutoQuarantiner` bir cihazı
karantinaya aldığında generic karantina-sonrası kanca bir check açar (kural-id boş →
"cihazda ARTIK herhangi bir tespit tetikliyor mu?"); arka-plan worker'ı pencere dolunca
yeniden değerlendirip çözer. Pencere: `KUT_VERIFY_WINDOW` (varsayılan 15dk).

## Metrikler

`kut_verify_verified_total`, `kut_verify_regressed_total` (Prometheus; /metrics).

## Kapsam-dışı (ilk sürüm)

Attack-path/graf-tabanlı doğrulama; `vuln`/`compliance` re-scan kind'ları; **predictive**
(what-if) beklenen risk-azalması ve simülasyon (ölçülen/gerçekleşen azalma yeterli); kalıcı
DB geçmişi (MemStore + Restore, casemgmt deseni). Bunlar rezerve/ileri fazlardır.
