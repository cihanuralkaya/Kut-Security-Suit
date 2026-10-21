# Command Fabric — İmzalı Cihaz Komutları: Tel Biçimi (DSSE), Güven Modeli, Sınırlar

Bu belge, sunucudan ajana giden cihaz komutlarının **imzalı zarf (envelope v2)** biçimini,
bu zarfı doğrulayan **güven bildirimi (trust statement)** modelini ve bilinen sınırları
tanımlar. İki nesne de standart bir **DSSE** (Dead Simple Signing Envelope) zarfıdır.
Kod: `cmdenvelope/dsse.go`, `cmdenvelope/v2.go`, `cmdenvelope/trust.go`; tel alanları:
`proto/kut/v1/{agent,common,enrollment}.proto`; sabit vektörler:
`contracts/testvectors/cmdenvelope/v2_vectors.json`.

`docs/CONTRACTS.md` §1-13 DONDURULMUŞTUR ve bu belge onu değiştirmez. §5 (`CommandEnvelope`)
ile eşleme aşağıda; bir §5 eki ayrı bir revizyon olarak ele alınır.

**Yol haritası eşlemesi.** Bu belgenin kapsadığı tel sözleşmesi ve altın vektörler: **WP-EP-001**
(wire contract v2 + golden vectors). Sunucu tarafı (kalıcılık, komut düzleminde imzalama/teslim,
bootstrap dağıtımı): **WP-CP-004**, sonraki dilimlerde (S3, S4, S5). Ajan doğrulayıcısı: S6.

## 1. Durum ve sürümleme

* **v1** (`cmdenvelope.CanonicalBytes`) hiçbir zaman tele çıkmadı; yalnız sunucu içi bir
  önizlemeydi. Baytları değişmedi ve bu belgenin kapsamı dışındadır.
* **v2, telde görülen İLK sürümdür.** Tel biçimi bu belgede ve `v2_vectors.json` içinde
  **dondurulmuştur**: gövde kodlaması, PAE, yük türleri, sınırlar, proto numaraları. Bunlardan
  birini değiştirmek bir ajan dağıtımı gerektirir; bu yüzden vektör dosyası yalnız `-update` ile,
  bilinçli olarak yeniden yazılır (bkz. "Altın vektörler").
* Sürüm **yük türünde** taşınır (`...cmd.v2`). `v1`/`v3` gibi başka bir sürüm
  `unsupported_version` ile reddedilir.
* `cmdenvelope` paketi yalnız standart kütüphaneyi kullanır (PAE ve DSSE JSON elle yazılmıştır);
  ajan bu paketi import eder.

## 2. DSSE zarfı

Biçim: [DSSE v1.0](https://github.com/secure-systems-lab/dsse) (`protocol.md`).

```
envelope = { payloadType, payload (bayt), signatures: [ { keyid, sig } ] }
sig      = Ed25519( PAE(payloadType, payload) )          // saf Ed25519, ön-özetleme yok
PAE      = "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

* `SP` = 0x20. `LEN` = bayt uzunluğunun **ASCII ondalık** gösterimi (başında sıfır yok).
  Örnek: `PAE("http://example.com/HelloWorld", "hello world")` =
  `DSSEv1 29 http://example.com/HelloWorld 11 hello world`.
* **Yük türleri** (PAE'ye dahildir; bir türün imzası başka bir tür olarak geçmez):
  `application/vnd.kut.cmd.v2` (komut) ve `application/vnd.kut.trust.v2` (güven bildirimi).
  Başka türler `bad_payload_type`, tanınan önekli ama farklı sürümler `unsupported_version`.
* **Gövde tüm imzacılar için AYNIDIR.** Anahtar kimliği gövdede yoktur; yalnız imza girdisindeki
  `keyid` içinde bulunur ve **doğrulanmamış bir ipucudur**: doğrulayan, güvendiği anahtarı `keyid` ile
  bulur ve imzayı O anahtarla doğrular. `keyid` yanlış anahtarı gösterirse imza doğrulanmaz
  (`bad_signature`), bilinmeyen ise `unknown_key` (geçici).
* `keyid = hex(sha256(açık_anahtar)[:16])` (32 küçük harfli hex, 128 bit).
* **Çoklu imza** (komut imzası + onaylayan imzası, rotasyon örtüşmesi): aynı gövdeye `signatures`
  listesinde birden çok girdi. En çok **8** girdi. Aynı `keyid` birden çok kez görünürse **bir kez
  sayılır**. Bilinmeyen imzacılar yok sayılır. Gereken ayrık geçerli imza sayısı
  `VerifyInput.MinSignatures` (0 ise `RequiredSignatures(type)` = 1). WIPE/UNINSTALL için 2 imzanın
  zorunlu kılınması ve `approved_by` ile onaylayan anahtarın bağlanması sonraki dilimlerdedir (S5/S8);
  tel biçimi ve doğrulayıcı kancası hazırdır.
* Boyut: gövde 1..4096 bayt, imza girdisi başına `keyid` 32 hex ve `sig` tam 64 bayt.
* **JSON gösterimi** standarttır: `{"payloadType","payload" (dolgulu std base64),"signatures":[{"keyid","sig"}]}`;
  `ParseDSSEJSON` katı ayrıştırır (bilinmeyen alan, artık veri, URL-safe/dolgusuz base64, aşırı boyut ret).

## 3. Komut gövdesi (`application/vnd.kut.cmd.v2`)

### 3.1 Kodlama

```
LP(x)  = uint32_BE(len(x)) || x       U64(n)/I64(n) = 8 bayt büyük-endian
payload = LP("kut-cmd-envelope-v2")
       || LP(command_id) || LP(device_id) || LP(tenant_id) || LP(type)
       || LP(requested_by) || LP(approved_by) || LP(correlation_id)
       || U64(sequence) || LP(nonce) || I64(issued_at_ns) || I64(expires_at_ns)
       || LP(params_digest)
```

Alan sırası yukarıdaki gibidir; etki alanı etiketi gövdenin İLK alanıdır (derinlemesine savunma).
`key_id` yoktur. `command_id` veritabanı satır kimliğiyle aynıdır.

### 3.2 Alan kuralları ve sert sınırlar

Sunucu tarafı imzalama ve ajan tarafı doğrulama **aynı** fonksiyonları (`Fields.Validate`,
`ValidateParams`) kullanır. Her dize ayrıca geçerli UTF-8 olmalı ve NUL içermemelidir.

| Alan | Kural |
|---|---|
| `command_id` | tam 36 karakter, kanonik küçük harfli UUIDv4 (büyük harf/süslü parantez/tiresiz ret) |
| `device_id` | 1..64 bayt, yazdırılabilir ASCII, **büyük harf yok** (ajan sertifika CN'ini küçük harfe çevirir). Doğrulayan gövdedeki değerin KENDİ kimliğine eşitliğini zorlar (`wrong_device`); doğrulayanın kendi kimliği kanonik değilse `bad_device_id` |
| `tenant_id` | 0..63 bayt, yazdırılabilir ASCII (0x21-0x7e); `""` = platform/tek kiracı. Sunucuda cihaz satırından çözülür, istekten alınmaz |
| `type` | 9 bilinen tip adından biri (`cmdenvelope/types.go`); bilinmeyen/boş ret, imzalı olsa bile |
| `requested_by` | 1..128 bayt, yazdırılabilir ASCII (`admin:<uuid>`, `system:auto-response`, `rule:<id>`, `ai:<id>`) |
| `approved_by` | 0..128 bayt, aynı karakter kümesi; boş değilse `requested_by` ile aynı olamaz. Çift kontrollü WIPE/UNINSTALL için sunucu zorunlu kılar |
| `correlation_id` | 0..128 bayt, aynı karakter kümesi; opak istek kimliği (CONTRACTS §5 AuthorizationCorrelationID); GrantID değildir |
| `sequence` | uint64, cihaz başına monoton (bkz. 3.3) |
| `nonce` | tam 32 küçük harfli hex (16 rastgele bayt) |
| `issued_at_ns` / `expires_at_ns` | UnixNano; `issued_at > 0`, `0 < expires - issued <= 31 gün`; saat toleransı 2 dk |
| `params` | **gövdede değil**, `params_digest` ile bağlanır; değerler yalnız `string` ya da `[]string`; ≤32 anahtar; anahtar `[a-z0-9_]{1,64}`; dize ≤256 KiB; toplam (anahtar+değer baytları) ≤512 KiB; liste ≤64 öğe |

Sayı, bool, null, iç içe nesne ya da karışık liste içeren parametreler `malformed_params` ile
reddedilir (`ParamsFromMap`); sunucu→JSONB→proto(structpb)→ajan yolunda özet değişmez.

### 3.3 Sequence

`sequence`, cihaz başına tek yönlü artan sayaçtan (sunucuda `devices.cmd_seq`, atomik artırma)
**imzalamadan önce** alınır; başarısız eklemede boşluk kalabilir. Ajan tarafı aile başına son
değeri tutar. `cmdenvelope.Family`: `isolation = {QUARANTINE, UNQUARANTINE}`, diğer her tip kendi ailesi.
Kural: isolation ailesinde **yeni** bir komut kimliğinin `sequence`'ı son değerin altındaysa
`superseded` (kalıcı ret). (Bu dilimde yalnız biçim donduruldu; atama ve zorlama sonraki dilimlerdedir.)

### 3.4 Params özeti

```
params_digest = SHA256( LP("kut-cmd-params-v2") || U32(n)
   || her anahtar için, anahtarlar bayt sırasıyla:
        LP(key) || 0x01 || LP(value)                    // dize
      | LP(key) || 0x02 || U32(count) || LP(item)*      // liste )
```

`nil` küme ile boş küme aynı özeti verir; `"x"` ile `["x"]` farklıdır. Params telde
`Command.params` (structpb) olarak taşınır; ajan özeti yeniden hesaplar ve gövdedekiyle karşılaştırır
(uyuşmazlık `bad_signature`). `ParseParams` sırasız/yinelenen anahtarı, artık baytı ve sınır
aşımını reddeder.

### 3.5 Doğrulama sırası (`VerifyV2`, durumsuz)

1. `payloadType` tam `application/vnd.kut.cmd.v2` olmalı (`unsupported_version` / `bad_payload_type`).
2. Doğrulayanın cihaz kimliği kanonik olmalı (`bad_device_id`).
3. DSSE biçimi: gövde boyutu, imza sayısı 1..8, `keyid`/`sig` biçimi (`malformed_envelope`).
4. Gövde KATI ayrıştırılır ve alan sınırları denetlenir (`malformed_envelope`, `unknown_type`,
   `bad_lifetime`, `bad_device_id`).
5. Gövdedeki `device_id` == doğrulayanın kimliği (`wrong_device`); telde taşınan `command_id`/`type`
   gövdeyle aynı (`malformed_envelope`).
6. Params sınırları (`malformed_params`).
7. Her imza girdisi için: `keyid` ile güvenilen **KOMUT** anahtarı bulunur; pencere
   `not_before <= issued_at <= not_after` dışındaysa `key_expired` (teslim anında dolmuş olsa da,
   imzalandığında geçerli anahtar kabul edilir); Ed25519 doğrulaması **PAE üzerinde**.
   Yeterli geçerli imza yoksa: bozuk imza `bad_signature`, bazı geçerli ama yetersiz
   `insufficient_signatures`, hiçbiri tanınmıyorsa `unknown_key` (geçici).
8. Params özeti gövdedekiyle aynı olmalı (`bad_signature`).
9. Zaman: saat yoksa `clock_unsynced` (geçici); `issued_at > now + 2 dk` → `not_yet_valid` (geçici);
   `now > expires_at` → `expired`.

Başarılı sonuç `Verified{Digest = sha256(PAE), KeyIDs, Fields}` döner; `Digest`,
`CommandResult.envelope_digest` olarak bildirilir. **Geçici** nedenler kalıcı ret olarak kaydedilmez
ve ack'lenmez.

## 4. Güven bildirimi (`application/vnd.kut.trust.v2`)

### 4.1 Biçim

```
KeyEntry{ key_id, pubkey(32), role = ROOT|COMMAND, not_before_ns, not_after_ns }
payload = LP("kut-cmd-trust-v2") || U64(epoch) || U32(root_threshold) || I64(issued_at_ns)
   || U32(min_verify_mode) || U64(min_agent_build) || U32(n)
   || her anahtar için (key_id sırasıyla): LP(key_id) || LP(pubkey) || U32(role) || I64(not_before) || I64(not_after)
```

DSSE `signatures` girdileri KÖK anahtarlarındır; imza `PAE("application/vnd.kut.trust.v2", payload)`
üzerindedir. Sınırlar: 1..32 anahtar, 1..8 imza, `epoch >= 1`, `1 <= root_threshold <= kök sayısı`,
`min_verify_mode ∈ {0 none, 1 warn, 2 enforce}`. KOMUT anahtarında `not_after != 0` **zorunludur**;
KÖK anahtarda `0` = süresiz. `key_id` açık anahtardan türemelidir. Gövdenin ayrıştırıcısı
(`ParseStatement`) sırasız/yinelenen anahtarı ve artık baytı reddeder.

### 4.2 Roller

* **KÖK (ROOT):** yalnız bildirim imzalar. Özel anahtarlar çevrimdışı tutulur, C2'ye girmez.
* **KOMUT (COMMAND):** yalnız komut zarfı imzalar; her birinin son kullanma zamanı vardır. KOMUT
  anahtarı bildirim imzalayamaz (imzası sayılmaz; yalnız komut imzası varsa `signer_not_root`).
* **Pin:** ajan ortamındaki `KUT_CMD_PUBKEY` (ve gömülü kök) bir KÖK pinidir; bildirimden bağımsızdır,
  sunucu bildirimiyle düşürülemez.

### 4.3 Kabul kuralları (`ApplyStatement` / `ApplyStatementDSSE`, saf)

Kota, **güvenilen KÖK anahtarların ayrık `keyid`'lerinden PAE üzerinde doğrulananların sayısıdır**;
`keyid` yalnız anahtarı bulmak için ipucudur.

1. İmzacılar KÖK rolünde olmalı.
2. **Pin kuralı:** pin kümesinden ≥1 anahtarın imzası, yerel epoch'tan büyük **her** epoch'u kabul ettirir.
3. **Zincir kuralı** (pin imzası yoksa): `epoch == yerel+1` ve **mevcut** kök kümesinden ≥
   `yerel.root_threshold` ayrık anahtar imzalamalı; kök kümesi değişiyorsa **yeni** kümeden ≥
   `st.root_threshold` ayrık anahtar da imzalamalı.
4. **Bootstrap:** yerel durum ve pin yoksa bildirim kendi kök eşiğiyle tutarlı olmalı. Pin
   tanımlıyken pin imzasız ilk bildirim `pin_required`. Bootstrap kabulü yalnız çağıranın ek koşulları
   (sunucu opt-in, sunset, SPKI pin) sağlanırsa geçerlidir; bunları bu fonksiyon denetlemez.
5. **İmzacı penceresi** bildirimin kendi `issued_at_ns` anında değerlendirilir; süresi dolmuş (ya da
   henüz başlamamış) kök anahtarın imzası sayılmaz. `issued_at_ns`, `now + 2 dk`'dan ileride olamaz
   (saat yoksa bu denetim atlanır).
6. Epoch asla azalmaz (`stale_epoch`). `min_verify_mode` ve `min_agent_build` yalnız yukarı ratchet
   eder (`Floors.Raise`).
7. Zincirler sırayla uygulanır (`ApplyChain`); başarısız halka durumu değiştirmez.

`VerifyChain` sunucunun zincir dosyası içindir: epoch'lar tam olarak 1..N, her halka kurallardan geçmeli.
`ActiveKeyValid` / `ChainKeyValid`, Aktif komut anahtarının güncel bildirimde KOMUT rolüyle bulunduğunu
ve `now` anında pencere içinde olduğunu denetler (önyükleme öz-denetimi).

Ret nedenleri: `malformed_statement`, `stale_epoch`, `epoch_skipped`, `threshold_not_met`,
`signer_not_root`, `pin_required`, `chain_incomplete`, `key_not_in_chain`, `bad_payload_type`,
`unsupported_version`, `not_yet_valid`, `key_expired`, `clock_unsynced`.

## 5. Tel eşlemesi (proto)

Tüm eklemeler katkısaldır (eski ajan yok sayar, eski sunucu boş bırakır). Komut ve bildirim aynı
`DsseEnvelope` mesajını kullanır:

```
message DsseEnvelope  { string payload_type=1; bytes payload=2; repeated DsseSignature signatures=3; }
message DsseSignature { string keyid=1; bytes sig=2; }

Command (1-8 değişmedi): DsseEnvelope envelope=9;     // varsa v2; yoksa eski/imzasız
        v2'de ajan YALNIZ gövdedeki değerlere güvenir; command_id(1), type(2), params(3) gövdeyle çapraz denetlenir
CommandResult:     bytes envelope_digest=5            // sha256(PAE(payload_type, payload))
EnrollResponse:    DsseEnvelope command_trust=5; TenantBinding tenant_binding=6
HeartbeatRequest:  uint64 trust_epoch=8; repeated string capabilities=9; uint64 agent_build=10
HeartbeatResponse: repeated DsseEnvelope trust_statements=5; TenantBinding tenant_binding=6
Ayrılmış (sonraki dilimler): PolicyBundle 5-11, UpdateManifest 8-12, AgentIdentity 5
```

`proto_freeze_test.go` her numarayı, türü ve ayırmayı sabitler; `buf lint` ve `buf breaking`
(`main`'e karşı) temizdir.

## 6. CONTRACTS §5 eşlemesi

CommandID ✔ · TenantID ✔ · DeviceID ✔ (gövdede; doğrulayan kendi kimliğine eşitliği zorlar) ·
Action ✔ (`type`) · ParametersHash ✔ (`params_digest`) · IssuedAt/ExpiresAt ✔ · Nonce ✔ ·
Signature ✔ (DSSE imzaları) · RequestID/AuthorizationCorrelationID ✔ (`correlation_id`) · Sequence ✔ ·
GrantID taşınmaz (yalnız sunucu içi). Katkısal ekler: `payloadType`, `keyid`, `requested_by`/`approved_by`,
çoklu imza.

## 7. Güven modelinin sınırları (bilinen, kasıtlı)

* **Tam ele geçirilmiş bir C2** geçerli komut anahtarıyla imzalayabilir: toplu QUARANTINE/LOCK/
  COLLECT_FILE ve silah kurulu cihazlarda WIPE mümkündür. İmzalı betikler bağımsız çevrimdışı betik
  anahtarıyla korunur. WIPE/UNINSTALL için ikinci (onaylayan) imza `MinSignatures` kancasıyla
  **hazırdır** ama W2'de zorunlu değildir.
* **DB yazma yetkisi** olan saldırgan imzalı bir komutu **sahteleyemez, değiştiremez, kırpamaz,
  sırasını bozamaz (sequence) ya da başka kiracıya taşıyamaz**; ancak teslimi geciktirebilir.
* Bildirim imzacı penceresi bildirimin **kendi** `issued_at_ns` alanına göre değerlendirilir; süresi
  dolmuş bir kök anahtarın sahibi geriye tarihli bir bildirim üretebilir. Hijyen önlemi: süresi dolan
  anahtarı eşik imzalı bir bildirimle kök kümesinden çıkarmak. Pin imzası bu pencereye tabi değildir.
* `keyid` doğrulanmamıştır; yanlış ipucu yalnızca doğrulamayı başarısız kılar, yetki vermez.
* Çalınmış cihaz sertifikasıyla ack yutma, TPM'e bağlı cihaz anahtarı olmadan tamamen kapanmaz.

## 8. Altın vektörler

`contracts/testvectors/cmdenvelope/v2_vectors.json`, sabit tohumlardan
(`sha256("kut-w2-vector-seed:"+ad)`) deterministik üretilir ve bayt-bayt sabitlenir. İçerik: PAE sabit
örnekleri; her komut sınıfı için geçerli DSSE zarfları; sıfırdan farklı ve azami `sequence`; çoklu imza
(iki anahtar güvenilir, yalnız ikincil güvenilir, bilinmeyen ek imzacı, yinelenen `keyid` bir kez sayılır,
ikinci imza zorunlu/eksik/bozuk); çift kontrollü WIPE'ta onaylayan imzası; yanlış yük türü; PAE olmadan
atılan imza; başka yük türüyle atılan imza; yanlış `keyid` ipucu; v1 ve bildirim imzalarının sunulması;
tüm alan/karakter/ömür/anahtar/zaman ret vakaları; params kodlamaları; ve güven senaryoları (genesis,
rotasyon, kaldırma, kök değişimi, pin imzalı atlama, eşik karşılanmaması, KOMUT anahtarı imzacısı, süresi
dolmuş anahtarlar, zincir dosyası denetimleri, DSSE imza işleme). Aynı dosya ajan testlerince okunur.

```
go test ./cmdenvelope -run TestGoldenVectors
go test ./cmdenvelope -run TestGoldenVectors_BytePinned -update   # YALNIZ bilinçli tel değişikliğinde
```

Üretici `cmdenvelope/internal/vectors` altındadır. Fuzz hedefleri: `FuzzParseCanonicalV2`,
`FuzzParseParams`, `FuzzParseStatement`, `FuzzVerifyV2`, `FuzzApplyStatement`, `FuzzParseDSSEJSON`
(`scripts/fuzz.sh`).

## 9. Bu dilimin kapsamı

Yalnız biçim ve saf doğrulayıcılar (WP-EP-001): kalıcılık, canlı imzalama/teslim ve ajan zorlaması
sonraki dilimlerdedir (WP-CP-004 ve ajan doğrulayıcısı). Bu belgenin tel biçimi o dilimlerde değişmez.
