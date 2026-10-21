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
  (`ErrTenantMismatch`); cihazın güvenlik durumu (karantina vb.) yeniden kayıtta korunur.
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
  emanet-zinciri (custody) kaydı, tespit yeniden-oynatma (replay).
- **İptal edilmiş sertifikalar**, devam ettirilen (resumed) TLS oturumlarında da
  `VerifyConnection` ile zorlanır; iptal listesi başlangıçta yüklenir.

Konsol bu kapılarla uyumludur: VIEWER oturumunda artefakt indirme denetimi gizlenir
(kilit simgesi), 403'ler mesajla ele alınır; MFA yeniden kayıt/kapatma mevcut kodu sorar;
enrollment token isteği kiracı göndermez (kiracı sunucuda çözülür).

## Değişmezler

- INV-044: kiracı çözülemiyorsa (zorlama açıkken) DENY.
- Kiracı istemci girdisinden ASLA alınmaz.
- Fail-closed: uyumsuz kiracı → reddet ya da "bulunamadı"; varlık sızdırılmaz.
