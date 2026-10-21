# Command Fabric — İmzalı Cihaz Komutları: Tel Biçimi, Güven Modeli, Sınırlar

Bu belge, sunucudan ajana giden cihaz komutlarının **imzalı zarf (envelope v2)** biçimini,
bu zarfı doğrulayan **güven bildirimi (trust statement)** modelini ve bilinen sınırları
tanımlar. Kod: `cmdenvelope/v2.go`, `cmdenvelope/trust.go`; tel alanları:
`proto/kut/v1/{agent,common,enrollment}.proto`; sabit vektörler:
`cmdenvelope/testdata/v2_vectors.json`.

`docs/CONTRACTS.md` §1-13 DONDURULMUŞTUR ve bu belge onu değiştirmez. §5 (`CommandEnvelope`)
ile eşleme aşağıda (bkz. "CONTRACTS §5 eşlemesi"); bir §5 eki ayrı bir revizyon olarak
ele alınır.

## 1. Durum ve sürümleme

* **v1** (`cmdenvelope.CanonicalBytes`) hiçbir zaman tele çıkmadı; yalnız sunucu içi bir
  önizlemeydi. Baytları değişmedi ve bu belgenin kapsamı dışındadır.
* **v2, telde görülen İLK sürümdür.** Tel biçimi bu belgede ve `v2_vectors.json` içinde
  **dondurulmuştur**: kanonik kodlama, alan sırası, sınırlar, proto numaraları. Bunlardan
  birini değiştirmek bir ajan dağıtımı gerektirir; bu yüzden değişiklik `-update` ile bilinçli
  yapılır (aşağıda "Altın vektörler").
* `cmdenvelope` paketi yalnız standart kütüphaneyi kullanır; ajan bu paketi import eder.

## 2. Zarf v2

### 2.1 Kodlama ilkeleri

```
LP(x)  = uint32_BE(len(x)) || x
U32(n) = 4 bayt büyük-endian işaretsiz
U64(n) = 8 bayt büyük-endian işaretsiz
I64(n) = 8 bayt büyük-endian ikiye tümleyen
```

İmzalanan ileti (saf Ed25519, ön-özetleme yok):

```
msg = LP("kut-cmd-envelope-v2")
   || LP(key_id) || LP(command_id) || LP(device_id) || LP(tenant_id)
   || LP(type)   || LP(requested_by) || LP(approved_by) || LP(correlation_id)
   || U64(sequence) || LP(nonce) || I64(issued_at_ns) || I64(expires_at_ns)
   || LP(params_digest)
signature = Ed25519.Sign(priv, msg)
```

* Her değişken uzunluklu alan uzunluk önekli olduğundan bitişik alanlar arasında bayt kaydırma
  aynı iletiyi üretemez.
* `key_id`, **o imzayı atan** anahtarın kimliğidir. `extra_signatures` içindeki her imza aynı
  iletiyi kendi `key_id`'siyle imzalar.
* Başka nesne türleri farklı etiketle başlar (`kut-cmd-trust-v2`, `kut-cmd-params-v2`, v1 etiketsiz):
  bir türün imzası başka bir tür olarak sunulduğunda doğrulanmaz.

### 2.2 Alan kuralları ve sert sınırlar

Sunucu tarafı imzalama ve ajan tarafı doğrulama **aynı** fonksiyonları (`Fields.Validate`,
`ValidateParams`) kullanır. Her dize ayrıca geçerli UTF-8 olmalı ve NUL içermemelidir.

| Alan | Kural |
|---|---|
| `key_id` | tam 32 küçük harfli hex = `hex(sha256(pub)[:16])` (128 bit) |
| `command_id` | tam 36 karakter, kanonik küçük harfli UUIDv4 (büyük harf/süslü parantez/tiresiz ret) |
| `device_id` | **telde YOK.** İmzalayan hedef cihazı, doğrulayan KENDİ kimliğini verir (ajan: istemci sertifikası CN'i, küçük harf). 1..64 bayt, yazdırılabilir ASCII, büyük harf yok |
| `tenant_id` | 0..63 bayt, yazdırılabilir ASCII (0x21-0x7e); `""` = platform/tek kiracı. Sunucuda cihaz satırından çözülür, istekten alınmaz |
| `type` | 9 bilinen tip adından biri (`cmdenvelope/types.go`); bilinmeyen/boş ret, imzalı olsa bile |
| `requested_by` | 1..128 bayt, yazdırılabilir ASCII (`admin:<uuid>`, `system:auto-response`, `rule:<id>`, `ai:<id>`) |
| `approved_by` | 0..128 bayt, aynı karakter kümesi; boş değilse `requested_by` ile aynı olamaz. Çift kontrollü WIPE/UNINSTALL için sunucu zorunlu kılar |
| `correlation_id` | 0..128 bayt, aynı karakter kümesi; opak istek kimliği (CONTRACTS §5 AuthorizationCorrelationID); GrantID değildir |
| `sequence` | uint64, cihaz başına monoton (bkz. 2.3) |
| `nonce` | tam 32 küçük harfli hex (16 rastgele bayt) |
| `issued_at_ns` / `expires_at_ns` | UnixNano; `issued_at > 0`, `0 < expires - issued <= 31 gün`; saat toleransı 2 dk |
| `params` | değerler yalnız `string` ya da `[]string`; ≤32 anahtar; anahtar `[a-z0-9_]{1,64}`; dize ≤256 KiB; toplam (anahtar+değer baytları) ≤512 KiB; liste ≤64 öğe |
| imzalar | birincil imza tam 64 bayt; `extra_signatures` ≤8, her biri geçerli `key_id` + 64 bayt, anahtarlar birbirinden ve birincilden farklı |

Sayı, bool, null, iç içe nesne ya da karışık liste içeren parametreler `malformed_params` ile
reddedilir (`ParamsFromMap`); sunucu→JSONB→proto(structpb)→ajan yolunda özet değişmez.

### 2.3 Sequence

`sequence`, cihaz başına tek yönlü artan sayaçtan (sunucuda `devices.cmd_seq`, atomik artırma)
**imzalamadan önce** alınır; başarısız eklemede boşluk kalabilir. Ajan tarafı aile başına son
değeri tutar. `cmdenvelope.Family` ailesi: `isolation = {QUARANTINE, UNQUARANTINE}`, diğer her tip
kendi ailesi. Kural: isolation ailesinde **yeni** bir komut kimliğinin `sequence`'ı son değerin
altındaysa `superseded` (kalıcı ret) — eski bir UNQUARANTINE, daha yeni bir QUARANTINE'den sonra
asla yürütülmez. Boşluk ve diğer ailelerde gerileme yalnız bilgi olayıdır. (Yalnız biçim tanımlıdır; atama ve zorlama ayrı bileşenlerin işidir.)

### 2.4 Params özeti

```
params_digest = SHA256( LP("kut-cmd-params-v2") || U32(n)
   || her anahtar için, anahtarlar bayt sırasıyla:
        LP(key) || 0x01 || LP(value)                    // dize
      | LP(key) || 0x02 || U32(len) || LP(item)*        // liste )
```

`nil` küme ile boş küme aynı özeti verir; `"x"` ile `["x"]` farklıdır. Ayrıştırıcı
(`ParseParams`) sırasız/yinelenen anahtarı, artık baytı ve sınır aşımını reddeder; başarılı
ayrıştırmanın yeniden kodlaması girdiyle bayt-bayt aynıdır.

### 2.5 Doğrulama sırası (`VerifyV2`, durumsuz)

1. `envelope_version == 2` (yoksa `unsupported_version`).
2. Tüm alan sınırları ve karakter kümeleri (`malformed_envelope`, `malformed_params`,
   `unknown_type`, `bad_lifetime`, `bad_device_id`).
3. İmza biçimi (64 bayt, ek imza kuralları) — `malformed_envelope`.
4. Güvenilen **KOMUT** rolündeki anahtarlar arasında `key_id` araması. Bilinmiyorsa
   `unknown_key` (**geçici**). Anahtar penceresi `not_before <= issued_at <= not_after` dışındaysa
   `key_expired`; yani teslim anında dolmuş olsa bile, imzalandığında geçerli anahtar kabul edilir.
5. Ed25519 doğrulaması (`bad_signature`). Gereken geçerli imza sayısı `RequiredSignatures(type)`
   = 1; bilinmeyen ek imzalar yok sayılır, ortak imza yeter.
6. Zaman: saat yoksa `clock_unsynced` (**geçici**); `issued_at > now + 2 dk` → `not_yet_valid`
   (**geçici**); `now > expires_at` → `expired`.

Başarılı sonuç `Verified{Digest = sha256(msg), KeyIDs}` döner; `Digest`, `CommandResult.envelope_digest`
olarak sunucuya bildirilir. **Geçici** nedenler kalıcı ret olarak kaydedilmez ve ack'lenmez.

## 3. Güven bildirimi (trust statement)

### 3.1 Biçim

```
KeyEntry{ key_id, pubkey(32), role = ROOT|COMMAND, not_before_ns, not_after_ns }
statement_msg = LP("kut-cmd-trust-v2") || U64(epoch) || U32(root_threshold) || I64(issued_at_ns)
   || U32(min_verify_mode) || U64(min_agent_build) || U32(n)
   || her anahtar için (key_id sırasıyla): LP(key_id) || LP(pubkey) || U32(role) || I64(not_before) || I64(not_after)
```

İmzalar iletiye dahil değildir; her imzacı aynı baytları imzalar. Sınırlar: 1..32 anahtar, ≤16 imza,
`epoch >= 1`, `1 <= root_threshold <= kök sayısı`, `min_verify_mode ∈ {0 none, 1 warn, 2 enforce}`.
KOMUT anahtarında `not_after != 0` **zorunludur**; KÖK anahtarda `0` = süresiz. `key_id` açık
anahtardan türemelidir. `role` proto'da `KeyRole` (ROOT=1, COMMAND=2) olup U32 değeri aynıdır.

### 3.2 Roller

* **KÖK (ROOT):** yalnız bildirim imzalar. Özel anahtarlar çevrimdışı tutulur, C2'ye girmez.
* **KOMUT (COMMAND):** yalnız komut zarfı imzalar; her birinin son kullanma zamanı vardır.
  KOMUT anahtarı bildirim imzalayamaz (imzası sayılmaz; yalnız komut imzası varsa `signer_not_root`).
* **Pin:** ajan ortamındaki `KUT_CMD_PUBKEY` (ve gömülü kök) bir KÖK pinidir; bildirimden bağımsızdır,
  sunucu bildirimiyle düşürülemez.

### 3.3 Kabul kuralları (`ApplyStatement`, saf)

1. İmzacılar KÖK rolünde olmalı.
2. **Pin kuralı:** pin kümesinden ≥1 anahtarın imzası, yerel epoch'tan büyük **her** epoch'u kabul
   ettirir (epoch atlaması = tek adımlı kurtarma).
3. **Zincir kuralı** (pin imzası yoksa): `epoch == yerel+1` ve **mevcut** kök kümesinden ≥
   `yerel.root_threshold` ayrık anahtar imzalamalı; kök kümesi değişiyorsa **yeni** kümeden ≥
   `st.root_threshold` ayrık anahtar da imzalamalı. Aynı `key_id` bir kez sayılır.
4. **Bootstrap:** yerel durum ve pin yoksa bildirim kendi kök eşiğiyle tutarlı olmalı. Pin
   tanımlıyken pin imzasız ilk bildirim `pin_required` ile reddedilir. Bootstrap kabulü yalnız
   çağıranın ek koşulları (sunucu opt-in, sunset, SPKI pin) sağlanırsa geçerlidir; bunları bu fonksiyon
   denetlemez.
5. **İmzacı penceresi** bildirimin kendi `issued_at_ns` anında değerlendirilir; süresi dolmuş (ya da
   henüz başlamamış) kök anahtarın imzası sayılmaz. `issued_at_ns`, `now + 2 dk`'dan ileride olamaz
   (saat yoksa bu denetim atlanır).
6. Epoch asla azalmaz (`stale_epoch`). `min_verify_mode` ve `min_agent_build` yalnız yukarı ratchet
   eder (`Floors.Raise`).
7. Bildirim zincirleri sırayla uygulanır (`ApplyChain`); başarısız halka durumu değiştirmez, son
   başarılı halka çağırana döner.

`VerifyChain`, sunucunun zincir dosyası içindir: epoch'lar tam olarak 1..N olmalı, her halka kurallardan
geçmeli (pin tanımlıysa epoch 1 pin imzalı). `ActiveKeyValid` / `ChainKeyValid`, Aktif komut
anahtarının güncel bildirimde KOMUT rolüyle bulunduğunu ve `now` anında pencere içinde olduğunu denetler
(önyükleme öz-denetimi).

Ret nedenleri: `malformed_statement`, `stale_epoch`, `epoch_skipped`, `threshold_not_met`,
`signer_not_root`, `pin_required`, `chain_incomplete`, `key_not_in_chain`, `not_yet_valid`,
`key_expired`, `clock_unsynced`.

## 4. Tel eşlemesi (proto)

Tüm eklemeler katkısaldır (eski ajan yok sayar, eski sunucu boş bırakır):

```
Command (1-8 değişmedi; v2'de signature=4, nonce=5, issued_at_unix=6, expires_at_unix=7 (UnixNano),
         issued_by=8 → requested_by):
  string tenant_id=9; uint32 envelope_version=10 (0 yok, 2 = v2; diğerleri reddedilir);
  string key_id=11; string correlation_id=12; uint64 sequence=13; string approved_by=14;
  repeated CommandSignature extra_signatures=15;   // {key_id, signature}
CommandResult:     bytes envelope_digest=5
TrustStatement / KeyEntry / TrustSignature / KeyRole / TenantBinding  (common.proto)
EnrollResponse:    TrustStatement command_trust=5; TenantBinding tenant_binding=6
HeartbeatRequest:  uint64 trust_epoch=8; repeated string capabilities=9; uint64 agent_build=10
HeartbeatResponse: repeated TrustStatement trust_statements=5; TenantBinding tenant_binding=6
Ayrılmış: PolicyBundle 5-11, UpdateManifest 8-12, AgentIdentity 5
```

`proto_freeze_test.go` her numarayı, türü ve ayırmayı sabitler.

## 5. CONTRACTS §5 eşlemesi

CommandID ✔ · TenantID ✔ · DeviceID ✔ (örtük: imza girdisinde, telde yok) · Action ✔ (`type`) ·
ParametersHash ✔ (`params_digest`) · IssuedAt/ExpiresAt ✔ · Nonce ✔ · Signature ✔ ·
RequestID/AuthorizationCorrelationID ✔ (`correlation_id`) · Sequence ✔ · GrantID taşınmaz
(yalnız sunucu içi). Katkısal ekler: `key_id`, `envelope_version`, `requested_by`/`approved_by`,
`extra_signatures`.

## 6. Güven modelinin sınırları (bilinen, kasıtlı)

* **Tam ele geçirilmiş bir C2** geçerli komut anahtarıyla imzalayabilir: toplu QUARANTINE/LOCK/
  COLLECT_FILE ve silah kurulu cihazlarda WIPE mümkündür. İmzalı betikler bağımsız çevrimdışı betik
  anahtarıyla korunur. WIPE/UNINSTALL için 2-of-N sınıfı `extra_signatures` ve
  `RequiredSignatures(type)` kancasıyla **ayrılmıştır** ama bu sürümde açık değildir.
* **DB yazma yetkisi** olan saldırgan imzalı bir komutu **sahteleyemez, değiştiremez, kırpamaz,
  sırasını bozamaz (sequence) ya da başka kiracıya taşıyamaz**; ancak teslimi geciktirebilir
  (engelleme `expired_undelivered` ve ack/sonuç ayrımıyla görünür kılınacaktır).
* Bildirim imzacı penceresi bildirimin **kendi** `issued_at_ns` alanına göre değerlendirilir; süresi
  dolmuş bir kök anahtarın sahibi geriye tarihli bir bildirim üretebilir. Hijyen önlemi: süresi dolan
  anahtarı eşik imzalı bir bildirimle kök kümesinden çıkarmak. Pin imzası bu pencereye tabi değildir.
* Çalınmış cihaz sertifikasıyla ack yutma, TPM'e bağlı cihaz anahtarı olmadan tamamen kapanmaz.
* Yerel yönetici ajan durum dosyalarını silebilir/geri alabilir; ratchet'in ikinci depo tasarımı
  ayrı bir bileşenin işidir.

## 7. Altın vektörler

`cmdenvelope/testdata/v2_vectors.json`, sabit tohumlardan (`sha256("kut-w2-vector-seed:"+ad)`)
deterministik üretilir ve bayt-bayt sabitlenir: her komut sınıfı için geçerli zarflar, sıfırdan farklı
ve azami `sequence`, ek imzalar, tüm ret vakaları, params kodlamaları ve güven senaryoları (genesis,
rotasyon, kaldırma, kök değişimi, pin imzalı atlama, eşik karşılanmaması, KOMUT anahtarı imzacısı,
süresi dolmuş anahtarlar, zincir dosyası denetimleri). Aynı dosya ajan testlerince okunur. Test:

```
go test ./cmdenvelope -run TestGoldenVectors
go test ./cmdenvelope -run TestGoldenVectors_BytePinned -update   # YALNIZ bilinçli tel değişikliğinde
```

Üretici `cmdenvelope/internal/vectors` altındadır. Fuzz hedefleri: `FuzzParseCanonicalV2`,
`FuzzParseParams`, `FuzzParseStatement`, `FuzzVerifyV2`, `FuzzApplyStatement` (`scripts/fuzz.sh`).

## 8. Kapsam

Bu belge yalnız biçimi ve saf doğrulayıcıları tanımlar: kalıcılık, canlı imzalama/teslim ve ajan
zorlaması ayrı bileşenlerdir. Bu belgenin tel biçimi onlarla değişmez.
