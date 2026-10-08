# ADR-0030: Continuous Exposure & Attack Surface Management Agent (AGENT-007)

## Durum
Kabul Edildi

## Bağlam
Saldırganlar çoğunlukla içerideki zayıflıkları aramadan önce dışa açık tehlikeli portları (RDP, SMB, FTP, Telnet), süresi dolmuş veya zayıf şifrelenmiş TLS sertifikalarını ve kamuya açık bilinen güvenlik açığı barındıran yazılımları (Log4j, OpenSSL CVEs) istismar eder. Sürekli Dış Saldırı Yüzeyi Yönetimi (External Attack Surface Management - EASM) ve maruziyet tespiti (Exposure Management), proaktif savunmanın temel taşıdır.

## Karar
`server/internal/aiprovider` paketi altında `ExposureAgent` devreye alındı:
1. **Sürekli Varlık Taraması (`ScanAsset`)**:
   - Varlığın açık portlarını, sertifika kalan gün sayısını ve çalışan yazılım sürümlerini değerlendirir.
2. **Tehlikeli Port Tespiti**:
   - Port 21 (FTP), 23 (Telnet), 3389 (RDP) ve 445 (SMB) gibi dışarıya açılmaması gereken portları `High` ciddiyet seviyesiyle işaretler ve izolasyon/güvenlik duvarı önerileri üretir.
3. **TLS Sertifika Değerlendirmesi**:
   - Süresi dolmuş (`<= 0`) veya dolmak üzere olan (`< 15 gün`) sertifikaları otomatik tespit eder.
4. **Bilinen Güvenlik Açığı Taraması**:
   - Log4Shell ve OpenSSL gibi kritik CVE'lere maruz kalan yazılımları tespit ederek yamalama eylem planı oluşturur.
5. **Kiracı İzolasyonu**:
   - Tüm bulgular varlık ve kiracı kimliğine bağlı olarak üretilir; kiracı sınırları korunur.

## Sonuçlar
- Kurum varlıklarının saldırı yüzeyi ve yapılandırma açıkları reaktif tespitlerden önce otonom şekilde saptanarak raporlanır.
