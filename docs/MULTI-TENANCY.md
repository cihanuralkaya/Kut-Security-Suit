# Multi-Tenancy — KUT Kiracı İzolasyon Modeli

KUT, **tek dağıtımda birden çok kiracıyı (müşteriyi)** güvenle barındıran paylaşımlı
bir SaaS modelini uygular. Kiracı ayrımı ayrı süreç/veritabanı ile DEĞİL, her varlığın
`tenant_id` taşıması ve her okuma/yazmanın çağıranın kiracısıyla daraltılmasıyla sağlanır.
(MSP, her müşteriyi ayrı dağıtıma değil; aynı dağıtımdaki bir `tenant_id`'ye eşler —
bkz. `msp_customers`.)

## Temel ilke — kiracı SUNUCU-TARAFI çözülür, istekten DEĞİL

Kiracı hiçbir zaman istemciden (header/gövde/parametre) alınmaz. Her zaman kimlik-
doğrulanmış bağlamdan türetilir:

| Yol | Kaynak |
|---|---|
| Ajan (yazma) | mTLS ile kimliklenen `device_id` → `devices.tenant_id` |
| Yönetici (okuma/aksiyon) | oturum admini `adminID` → `admins.tenant_id` |
| Olay triyajı | `event_id` → `event_logs.tenant_id` |

**Platform admini** = `admins.tenant_id` boş → TÜM kiracıları görür/yönetir (operatör/süper-
admin). **Kiracıya bağlı admin** = boş-olmayan `tenant_id` → yalnız kendi kiracısı.
Uyumsuzluk **fail-closed**: `ErrForbidden` ya da "bulunamadı" (varlık sızmaz).

## Yazma yolu (write path)

1. **Enrollment**: kayıt token'ı bir kiracı taşır (`enrollment_tokens.tenant_id`);
   cihaz kayıtta bu kiracıyı devralır (`devices.tenant_id`).
2. **Olay alımı**: handler cihazın kiracısını `TenantForDevice(device_id)` ile çözer ve
   her olayı sunucu-tarafı damgalar (`event_logs.tenant_id`) — istemcinin gönderdiği
   değere GÜVENİLMEZ.
3. **Zorlama**: `KUT_TENANT_ENFORCE=1` iken kiracıya bağlı OLMAYAN bir cihazın olayları
   `FailedPrecondition` ile reddedilir (INV-044: eksik kiracı → DENY). Varsayılan kapalı
   (geriye-uyumlu).

## Cihaz aksiyonları (yazma) ve olay triyajı

Yüksek-etkili/yıkıcı aksiyonlar rol + Scope/ROE'ye ek olarak **kiracı kapısından** geçer
(`enforceDeviceTenant`): lock, restart, quarantine, release, collect-diagnostics, wipe,
wipe-approve, wipe-cancel, collect-file, erase, revoke, assign-policy. Kiracıya bağlı bir
admin başka kiracının `device_id`'siyle aksiyon çalıştıramaz. Aynı biçimde olay triyaj
yazmaları (ack/resolve, sorumlu/not) `enforceEventTenant` ile olayın kiracısına bağlanır.

## Okuma yolu (read path)

Her yönetici okuma ucu çağıranın kiracısını çözüp sonucu daraltır. Kapsam:

- Olay listesi + retro-hunt + detection-replay (`EventFilter.TenantID`)
- Cihaz listesi + cihaz detayı (çapraz-kiracı cihaz "bulunamadı")
- Özet/KPI agregatları (durum/önem/kategori sayımları, uyum)
- Coverage, framework-compliance, fleet-risk
- Incident'ler + incident zaman çizelgesi (device→tenant join)
- Yazılım envanteri + zafiyet görünümü
- Artefaktlar + delil + gözetim-zinciri + artefakt indirme (device→tenant)
- Denetim izi + kayıtlı aramalar (admin→tenant join)
- SOC vakaları (list/get/transition/attach) + varlık grafı pivot/anomaly
- Enrollment token listesi + bekleyen WIPE listesi
- Cihaz-kapsamlı olay okumaları (attack-story, entity-graph, export)

Platform admini boş kiracıyla TÜMÜNÜ görür (gerekli yerde `ListAll`/`GetAny`/`*Any`
kiracı-agnostik yollar).

## Ayrıcalık-yükseltme koruması

`CreateAdmin`: istemcinin verdiği `tenant_id` yalnızca ÖNERİDİR. Oluşturan yöneticinin
kendi kiracısı sunucu-tarafı çözülür; kiracıya bağlı bir admin BAŞKA kiracıya admin
ekleyemez (fail-closed), boş istek kendi kiracısına sabitlenir. Platform admini herhangi
bir kiracıya ekleyebilir.

## Bilinçli kiracı-üstü (fleet-geneli) yüzeyler

Bazı uçlar tasarım gereği kiracılar-üstüdür ve bu bir sızıntı değildir:

- `GET /metrics` — operatör/Prometheus, statik token ile; dağıtım-geneli.
- Periyodik güvenlik-duruş raporu — dağıtımın `KUT_TENANT_ID`'siyle etiketlenir.
- Zamanlanmış kayıtlı-arama koşucusu + yönetici-davranışı (UEBA) — sistem analitiği.

## Altyapı-seviyesi izolasyon (dağıtım konfigü)

Uygulama katmanı her satır/anahtar/vakayı `tenant_id`-atıflı yapar. Derinlemesine-savunma
için altyapı katmanı da yapılandırılabilir (kod değil, dağıtım): ClickHouse tablo/row-
policy/quota, nesne-depolama (S3) kiracı-önekli anahtarlar, dayanıklı-bus partition/ACL.

## Sonradan kapsanan izolasyon seti (kiracı duvarı kapanışı)

Aşağıdaki yüzeyler de kiracı duvarına ve rol kapısına bağlanmıştır:

- **Enrollment token**: kiracı token'a sunucu tarafında mühürlenir (kiracıya bağlı admin
  başka kiracı veremez; gövdedeki `tenant_id` yalnız platform admini için geçerlidir) ve
  iptal (revoke) kiracı + OPERATOR kapısındandır; yabancı/yok token fail-closed reddedilir.
- **Cihaz yeniden-taşıma yok**: enroll sırasında mevcut cihaz başka kiracıya taşınamaz
  (MAC yolunda başka kiracının aynı MAC'i o satıra dokunmaz ve kendi cihazını alır — bkz. W1b-1
  S-3; token'a bağlı cihaz yolunda `ErrTenantMismatch`); cihazın güvenlik durumu (karantina vb.)
  yeniden kayıtta korunur.
  Kiracı öncesi (legacy) cihazların boş kiracısı örtük `default` kiracıyla eşdeğer sayılır:
  `default` token'ıyla yeniden kayıt reddedilmez ve kiracı `default`'a normalleştirilir
  (gerçek hiçbir kiracıya taşıma yine yok).
- **Yönetici yönetimi**: oluşturma/rol/pasifleştirme/listeleme kiracı kapsamlıdır ve
  kapsam dışına rol (ADMIN dahil) veremez; kapsamın SON etkin ADMIN'i kendini düşüremez
  veya pasifleştiremez (403, kilitlenme koruması; platform kapsamı için de geçerlidir).
- **Yönetilen API token'ları** (metrics/ingest; oluştur/listele/iptal): yalnız platform
  admini; kiracıya bağlı admin 403 alır.
- **Cihaz etiketleri**: OPERATOR+ ve cihazın kiracısı ile sınırlı.
- **MFA yeniden kayıt**: MFA zaten etkinse `POST /api/mfa/enroll` mevcut TOTP kodunu
  (`{"code":"…"}`) ister; kodsuz/yanlış/tekrar kullanılmış kod 403 + denetim kaydıdır.
  Yeni sır BEKLEYEN olarak ayrı saklanır: yeni sırdan gelen geçerli kodla etkinleşene dek
  eski sır ve `mfa_enrolled` aynen kalır (giriş MFA'yı zorunlu kılar, kapatma eski sırdan
  kod ister); etkinleşmede takas atomiktir ve eski sır geçersizleşir.
- **Adli (forensics) uçları** OPERATOR+ gerektirir (VIEWER 403): artefakt indirme,
  emanet-zinciri (custody) kaydı, tespit yeniden-oynatma (replay) ve (W1b-1) artefakt/delil
  LİSTELEME (`GET /api/devices/{id}/artifacts`, `/evidence`).
- **İptal edilmiş sertifikalar**, devam ettirilen (resumed) TLS oturumlarında da
  `VerifyConnection` ile zorlanır; iptal listesi başlangıçta yüklenir.

Konsol bu kapılarla uyumludur: VIEWER oturumunda artefakt indirme denetimi gizlenir
(kilit simgesi), 403'ler mesajla ele alınır; MFA yeniden kayıt/kapatma mevcut kodu sorar;
enrollment token isteği kiracı göndermez (kiracı sunucuda çözülür).

## W1b-1 — Kiracı Duvarı II: veri ve yönetim katmanı

- **MAC tekilliği kiracı başınadır (S-3)**: `devices.mac_address_bidx` artık küresel UNIQUE
  değildir; tekillik anahtarı `uq_devices_tenant_mac` = (kanonik kiracı, MAC). Kanonik kiracı
  `COALESCE(NULLIF(tenant_id,''),'default')`'tır: kiracı öncesi boş kiracı, `default` ile
  AYNI kiracıdır (`tenant.Canonical`), böylece `''` ve `default` aynı MAC için iki satır
  üretemez. Bir kiracı başkasının MAC'ini önceden kaydederek onu engelleyemez (MAC-squat DoS);
  aynı MAC başka kiracıda ayrı satır olur ve mevcut satıra DOKUNULMAZ (re-home yok).
- **Yazma yollarında SQL kiracı predicate'i (S-4)**: enrollment-token iptali, yönetici
  rol/pasifleştirme ve cihaz etiketi `UPDATE`'leri çağıranın kiracısını `AND tenant_id = $n`
  ile taşır. Platform çağıran boş kiracı verir (süzme yok). Kiracıya bağlı çağıran için eşleşen
  satır yoksa `ErrForbidden` (403): servis katmanındaki bir hata kiracı sınırını aşamaz.
- **Bilinmeyen/pasif yönetici platform değildir (S-5 / Z4b-09)**: `AdminTenant` bilinmeyen,
  bozuk-id'li veya pasif yönetici için `""` döndürmez; `ErrUnknownAdmin` (`ErrForbidden`'ı sarar,
  HTTP 403) döner. Tüm çağıranlar (servis kapıları, okuma kapsamı, platform-yalnız kontroller)
  hatayı yayar; boş kiracı yalnız ETKİN bir platform adminini ifade eder.
- **Politikalar kiracı sahibi taşır (Z4a-04 / Z4b-04)**: `policies.tenant_id` (varsayılan `''` =
  platform/paylaşımlı; mevcut tüm politikalar böyle kalır). Kiracıya bağlı admin yalnız KENDİ
  kiracısının politikalarını listeler/oluşturur/değiştirir (kural ekleme); paylaşımlı politikalar
  onlar için salt-okunur ve atanabilirdir; başka kiracının politikasına erişim yoktur (listede
  görünmez, kural listesi/kural ekleme/atama 403). Sahip SUNUCU-TARAFI çözülür; yalnız platform
  admini (doğrulanmış `tenant.Normalize`) kiracı seçebilir. Atama bütünlüğü: politika paylaşımlı
  ya da cihazın kiracısına ait olmalı — platform admini dahil herkes için ve SQL'de ayrıca;
  kural itmesi yalnız politikanın kiracısındaki cihazlara ulaşır; ajan politika çekimi eski
  çapraz-kiracı atamayı atlar.
- **Triyaj ve incident'lerde gerçek kiracı (Z4b-11)**: `event_ack.tenant_id` olayın kiracısıyla
  (ack ve vaka yolları), `incidents.tenant_id` cihazın kiracısıyla yazılır; kiracı daima
  sunucu-tarafı olaydan/cihazdan okunur. Boş (legacy) kiracı `tenant.Canonical` ile `default`
  olarak saklanır. Okuma yolları bilinçli olarak DEĞİŞMEDİ (backfill yapılmadığı için
  `event_ack.tenant_id` ile süzmek mevcut satırları gizlerdi).
- **Sınırda kiracı doğrulaması (Z4b-08)**: istekten gelen kiracı değerleri `tenant.Normalize`
  ile (kırp + küçük harf + `[a-z0-9-]`, 1-63) doğrulanır: yönetici oluşturma, MSP müşterisi,
  politika oluşturma, enrollment token ve yalnız-platform `?tenant=` filtresi (geçersiz → 400).
  Yönetici oluşturmada boş kiracı boş KALIR (platform admini).
- **Adli kayıt**: artefakt/delil listeleme OPERATOR+ (dosya yolları + gözetim zinciri aktörleri
  içerir); başarılı gözetim yazımı yönetici denetim izine `CUSTODY_<EYLEM>` olarak da düşer.

### Mevcut kurulumlar için yükseltme (W1b-1)

1. Şema bloğunu uygulayın (idempotent, yeniden çalıştırılabilir; taze kurulumda no-op):
   `sed -n '/^-- BEGIN W1B1-UPGRADE/,/^-- END W1B1-UPGRADE/p' db/schema.sql | psql "$KUT_DATABASE_URL"`.
   Blok önce yeni `uq_devices_tenant_mac` indeksini oluşturur, SONRA eski küresel
   `devices_mac_address_bidx_key` kısıtını düşürür; `policies.tenant_id` sütununu ekler.
2. Yeni ikiliyi AYNI bakım penceresinde dağıtın: eski ikili `ON CONFLICT (mac_address_bidx)`
   kullandığından kısıt düşünce cihaz kaydı (enroll) çalışmaz; yeni ikili ise `policies.tenant_id`
   sütununu bekler. İki adım arası yalnız enroll/politika uçları etkilenir.
3. Geri alma: `ALTER TABLE devices ADD CONSTRAINT devices_mac_address_bidx_key UNIQUE
   (mac_address_bidx)` yalnız farklı kiracılarda aynı MAC'li satır YOKSA başarılır; önce mükerrerleri
   çözün.
4. İsteğe bağlı, tek seferlik backfill (geçmiş satırları yeni temsile çevirir; tekrar çalıştırılabilir,
   bir transaction içinde uygulayın). Yeni yazımlar zaten doğru kiracıyı taşır; bu yalnız eski
   satırlar içindir:

```sql
BEGIN;
-- event_ack: olayın kiracısından (boş = 'default'). Eski hata: her satır 'default' idi.
UPDATE event_ack ea
   SET tenant_id = COALESCE(NULLIF(el.tenant_id, ''), 'default')
  FROM event_logs el
 WHERE el.id::text = ea.event_id
   AND ea.tenant_id <> COALESCE(NULLIF(el.tenant_id, ''), 'default');

-- incidents: cihazın kiracısından; cihazsız incident 'default'.
UPDATE incidents i
   SET tenant_id = COALESCE(NULLIF(d.tenant_id, ''), 'default')
  FROM devices d
 WHERE d.id = i.device_id
   AND i.tenant_id <> COALESCE(NULLIF(d.tenant_id, ''), 'default');
UPDATE incidents SET tenant_id = 'default' WHERE device_id IS NULL AND tenant_id = '';
COMMIT;
```

   Politikalar: mevcut politikalar paylaşımlı (`tenant_id = ''`) kalır. Bir politikayı bir kiracıya
   sahiplendirmek için `UPDATE policies SET tenant_id = '<kiracı>' WHERE id = '<uuid>'`. Yükseltmeden
   ÖNCE oluşmuş çapraz-kiracı atamaları bulmak için:

```sql
SELECT dp.device_id, dp.policy_id, d.tenant_id AS cihaz_kiracisi, p.tenant_id AS politika_kiracisi
  FROM device_policies dp
  JOIN devices  d ON d.id = dp.device_id
  JOIN policies p ON p.id = dp.policy_id
 WHERE p.tenant_id <> ''
   AND p.tenant_id <> COALESCE(NULLIF(d.tenant_id, ''), 'default');
```

   Bu atamalar ajana ZATEN itilmez (politika çekimi kiracı eşleşmesi arar); satırları temizlemek
   için `DELETE FROM device_policies` ile ilgili çiftleri silin.

## Değişmezler

- INV-044: kiracı çözülemiyorsa (zorlama açıkken) DENY.
- Kiracı istemci girdisinden ASLA alınmaz.
- Fail-closed: uyumsuz kiracı → reddet ya da "bulunamadı"; varlık sızdırılmaz.
