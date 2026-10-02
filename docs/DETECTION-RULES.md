# Tespit Kuralları — KUT Yerleşik Katalog

KUT, sunucu-taraflı deterministik bir tespit motoruyla (`server/internal/detect`)
gelen olayları MITRE ATT&CK teknikleriyle etiketler. Bu belge **yerleşik kural
kataloğunu** (`DefaultRules()`) ve motorun davranışını operatör/denetçi için
özetler. Kaynak doğruluğu: kurallar koddan türetilmiştir; her kural tekniği
`mitre.Catalog()` ile hizalıdır (`TestAllRuleTechniquesInCatalog` bunu CI'da
zorlar) ve `/api/mitre/coverage` paneli kapsamı buradan gösterir.

## Motor davranışı

- **Deterministik ve fail-closed değerlendirme.** Motor olayı kurallara karşı
  değerlendirir; eşleşen her kural bir `Detection` (kural-id, önem, teknik) üretir.
  AI/olasılıksal değildir — ya eşleşir ya eşleşmez.
- **Eşleşme türleri:**
  - `Contains` — mesajda verilen tüm alt-dizgiler (küçük/büyük harf duyarsız, AND) geçmeli.
  - `MessageRegex` — mesaj bu regex'e uymalı (`(?i)` ön-ekli, harf duyarsız). IOC-desen kuralları bunu kullanır.
  - `Absent` — dışlama literali; mevcutsa eşleşme iptal (yanlış-pozitif azaltma).
  - `Sequence` — mesajda sırayla geçmesi gereken literaller (opsiyonel `WithinBytes`).
  - `Fields` — olayın yapısal `Details` JSON alanlarıyla eşleşme.
  - `Threshold` — pencere içinde N kez (ör. kaba-kuvvet); `Track` sayaç kapsamı (device).
- **Kategori-bağımsızlık (IOC kuralları).** `MessageRegex` (IOC-desen) kuralları
  **kategori filtresi taşımaz**: aynı saldırgan deseni farklı telemetri
  kaynaklarından farklı kategorilerle gelir (aşağı bkz.). Spesifiklik regex'in
  kendisindedir. `Contains`-tabanlı kurallar kategori-semantiğini taşıdığından
  kategorilerini korur.
- **Yaşam döngüsü.** Kurallar etkin/pasif olabilir; pasif kurallar değerlendirilmez.

## Telemetri kaynakları (bir kural ne zaman tetiklenir?)

Bir kural, bir olay **mesajı** (bazen `Details`) örüntüsüyle eşleştiğinde tetiklenir.
Aynı saldırganın davranışı kaynağa göre farklı kategori/içerikle gelebilir:

| Kaynak | Kategori | İçerik | Örnek kural |
|---|---|---|---|
| Ajan native süreç izleme (`enforce/monitor`) | `PROCESS` | Süreç adı + pid/ppid; **Linux'ta komut-satırı** (`/proc/<pid>/cmdline`) | KUT-0023 (ad), KUT-0026 (Linux cmdline) |
| Windows Olay Günlüğü 4688 (süreç oluşturma) | `PROCESS` | Render mesajı + komut-satırı (denetim açıkken) | KUT-0015/0016/0026 |
| Sysmon EID 1 (süreç oluşturma) | `PROCESS` | Komut-satırı | KUT-0007/0023 |
| Sysmon EID 8 (CreateRemoteThread) | `SECURITY` | Enjeksiyon göstergesi | KUT-0025 |
| Sysmon EID 12/13 (registry) | `SECURITY` | Kayıt defteri işlemi | KUT-0026 |
| Windows Security 4697/4720/4728 (hizmet/hesap) | `SECURITY` | Kalıcılık/yetki olayı | KUT-0015/0017/0018 |
| Windows Security 4625 (başarısız oturum) | `SECURITY` | Kaba-kuvvet | KUT-0019 |
| Microsoft Defender 1116/1117 (kötü amaçlı yazılım) | `SECURITY` | Defender tespiti (ad+önem) | — (doğrudan alarm) |
| Microsoft Defender 5001/5010/5012 (koruma/tarama devre dışı) | `SECURITY` | Savunma etkisizleştirme | Classify → T1562 |

> **Not (Windows komut-satırı):** 4688 komut-satırı alanı yalnızca "Process Creation
> command line auditing" GPO'su etkinken doldurulur. Alım: `POST /api/ingest?format=winlog`
> (winlogbeat/nxlog/render-XML). Ayrıntı: [INGEST.md](INGEST.md).

Kategori-bağımsızlık sayesinde bir IOC-desen kuralı, deseni **hangi kaynak taşırsa
taşısın** tetiklenir (ör. KUT-0025 hem Sysmon-8 SECURITY hem başka bir süreç olayından).

## Yerleşik kural kataloğu (KUT-0001 … KUT-0031)

| ID | Ad | ATT&CK | Taktik | Önem | Eşleşme / gösterge |
|---|---|---|---|---|---|
| KUT-0001 | Ajan kurcalama girişimi | T1562 | Defense Evasion | CRITICAL | `kurcalama` (SECURITY) |
| KUT-0002 | İmzasız/sahte script reddedildi | T1059 | Execution | HIGH | `script` (SECURITY) |
| KUT-0003 | Sahte/bozuk OTA güncelleme reddedildi | T1195 | Initial Access | HIGH | `güncelleme` (SECURITY) |
| KUT-0004 | Davranışsal anomali | T1055 | Defense Evasion | HIGH | `anomali` (SECURITY) |
| KUT-0005 | Yasaklı süreç yürütmesi | T1204 | Execution | HIGH | kategori: POLICY_VIOLATION |
| KUT-0006 | Ağ hizmet keşfi | T1046 | Discovery | LOW | kategori: NETWORK_DISCOVERY |
| KUT-0007 | Şüpheli süreç/araç yürütmesi | T1059 | Execution | HIGH | mimikatz, psexec, nc.exe/ncat, `powershell -enc`, `certutil -urlcache`, rundll32/regsvr32 scrobj |
| KUT-0008 | Kalıcılık (autostart) girdisi | T1547 | Persistence | HIGH | `kalıcılık` (POLICY_VIOLATION) |
| KUT-0009 | Dosya bütünlüğü değişikliği (FIM) | T1070 | Defense Evasion | MEDIUM | `dosya bütünlüğü` (SECURITY) |
| KUT-0010 | DLP — hassas veri sızıntısı | T1048 | Exfiltration | HIGH | `hassas veri` (SECURITY) |
| KUT-0011 | DGA-şüpheli DNS sorgusu | T1071 | Command and Control | HIGH | `dga` (SECURITY) |
| KUT-0012 | İçerik-tarama eşleşmesi | T1105 | Command and Control | HIGH | `içerik-tarama` (SECURITY) |
| KUT-0013 | Yanal hareket / iç-ağ tarama | T1046 | Discovery | HIGH | `yanal hareket` (SECURITY) |
| KUT-0014 | DNS tünelleme / veri sızdırma | T1071 | Command and Control | HIGH | `dns tünelleme` (SECURITY) |
| KUT-0015 | Sistem servisi oluşturma/değiştirme | T1543 | Persistence | HIGH | `sc … create`, New/Set-Service, `systemctl enable/start`, /etc/systemd/system |
| KUT-0016 | Zamanlanmış görev/iş oluşturma | T1053 | Execution | HIGH | `schtasks /create`, New/Register-ScheduledTask, `crontab -`, /etc/cron |
| KUT-0017 | Yeni hesap oluşturma | T1136 | Persistence | HIGH | `net user … /add`, New-LocalUser, useradd/adduser |
| KUT-0018 | Hesap manipülasyonu (yetki/grup) | T1098 | Persistence | HIGH | `net localgroup administrators … /add`, Add-ADGroupMember, `usermod -aG` |
| KUT-0019 | Kaba-kuvvet / parola püskürtme | T1110 | Credential Access | HIGH | başarısız oturum / 4625 / brute — **eşik: 5/300sn/cihaz** |
| KUT-0020 | Fidye yazılımı — kitlesel şifreleme | T1486 | Impact | CRITICAL | ransom/fidye, `.encrypted`/`.locked`, decrypt talimatları |
| KUT-0021 | Sistem kurtarmayı engelleme | T1490 | Impact | CRITICAL | vssadmin delete shadows, wmic shadowcopy delete, wbadmin delete, bcdedit |
| KUT-0022 | Kimlik-bilgisi boşaltma (LSASS/SAM) | T1003 | Credential Access | CRITICAL | lsass dump, procdump lsass, comsvcs minidump, `reg save sam/security/system`, sekurlsa/lsadump |
| KUT-0023 | İmzalı ikiliyle vekil yürütme (LOLBin) | T1218 | Defense Evasion | HIGH | mshta, installutil, cmstp, odbcconf, mavinject, `forfiles /c`, msiexec (uzak/DLL) |
| KUT-0024 | Uzak hizmetlerle yanal yürütme | T1021 | Lateral Movement | HIGH | psexec/paexec, `wmic /node:`, Invoke-Command -ComputerName, Enter/New-PSSession, winrm/winrs, wmiexec/smbexec/dcomexec, `mstsc /v:` |
| KUT-0025 | Süreç enjeksiyonu | T1055 | Defense Evasion | HIGH | CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, QueueUserAPC, SetWindowsHookEx, reflective load, process hollow |
| KUT-0026 | Kayıt defteri değişikliği | T1112 | Defense Evasion | HIGH | `reg add/delete/import`, New/Set-ItemProperty HK*, Run anahtarı yazımı |
| KUT-0027 | Yetki yükseltme kötüye kullanımı (UAC bypass) | T1548 | Privilege Escalation | HIGH | fodhelper, eventvwr, sdclt, computerdefaults, bypassuac/UACME, CMSTPLUA/ICMLuaUtil |
| KUT-0028 | Kılık değiştirme (masquerading) | T1036 | Defense Evasion | HIGH | sistem-süreç adı (svchost/lsass/…) temp/appdata/… yolunda; çift uzantı (`*.pdf.exe`) |
| KUT-0029 | Güvenlik aracı/güvenlik duvarı devre dışı | T1562 | Defense Evasion | HIGH | Set/Add-MpPreference -Disable…, `netsh advfirewall … state off`, `sc stop/config windefend`, `Stop-Service windefend` |
| KUT-0030 | İz temizleme — olay günlüğü/dosya silme | T1070 | Defense Evasion | HIGH | `wevtutil cl`, Clear-EventLog, `fsutil usn deletejournal`, sdelete, `Remove-Item *.evtx` |
| KUT-0031 | WMI ile yürütme | T1047 | Execution | HIGH | `wmic … process call create`, Invoke-WmiMethod Win32_Process, Get-WmiObject Win32_Process … Create, Invoke-CimMethod Win32_Process |

> **Not (derinlik vs kapsam):** KUT-0029 (T1562) ve KUT-0030 (T1070), zaten kataloğda
> olan tekniklere **komut-tabanlı tespit derinliği** ekler (KUT-0001 yalnız "kurcalama",
> KUT-0009 yalnız FIM yakalıyordu); aynı teknik hücresini paylaşırlar. KUT-0031 (T1047)
> yeni bir teknik hücresidir.

**Özet kapsam:** 31 kural, 25 ayrı ATT&CK tekniği (`mitre.Catalog()` ile birebir); taktikler: Initial Access,
Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access,
Discovery, Lateral Movement, Command and Control, Exfiltration, Impact.

## Alarm zenginleştirme

Bir olay alarm ürettiğinde (`grpc/agent_handler`), `mitre.Classify(category, message)`
ile ATT&CK tekniği (id/ad/taktik) olarak zenginleştirilir. Classify, yukarıdaki
saldırı desenlerini (fidye/vssadmin/lsass/mshta/psexec/fodhelper/masquerade/registry)
doğru tekniğe eşler; eşleşmeyen SECURITY olayları savunma-etkisizleştirme (T1562)
varsayar.

## Kapsamı görüntüleme / genişletme

- **Konsol:** Güvenlik görünümü → ATT&CK kapsam paneli (`/api/mitre/coverage` +
  `/api/detections/rules`): her teknik için etkin kural sayısı / "boşluk".
- **Dry-run:** `POST /api/detections/test` (kategori + mesaj) → eşleşen kurallar
  (gerçek olay beklemeden kapsam doğrulama).
- **Yeni kural eklerken:** `detect.DefaultRules()`'a kuralı ekleyin **ve** tekniğini
  `mitre.Catalog()`'a ekleyin (aksi halde `TestAllRuleTechniquesInCatalog` CI'da
  kırılır ve teknik kapsam panelinde görünmez). IOC-desen (MessageRegex) kuralları
  `Category` ALMAZ. Pozitif kapsam + yanlış-pozitif (benign) testi yazın.
