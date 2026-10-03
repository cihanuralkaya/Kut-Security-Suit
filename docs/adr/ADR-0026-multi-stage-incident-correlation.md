# ADR-0026: Multi-Stage Incident Correlation Engine (XDR-005)

## Durum
Kabul Edildi

## Bağlam
Modern gelişmiş tehditler (APT) tekil bir uyarı yerine günlere veya saatlere yayılan çok aşamalı (multi-stage) zincirlerle ilerler (Initial Access -> Execution -> Persistence -> Lateral Movement -> Exfiltration). Güvenlik analistlerinin tekil uyarılar arasında kaybolmasını önlemek için aynı varlığa ait uyarılar kayan zaman penceresinde kümelenmeli ve MITRE ATT&CK taktik yayılımına göre vaka ciddiyeti otomatik yükseltilmelidir.

## Karar
`server/internal/telemetryplane` paketinde `CorrelationEngine` uygulandı:
1. **Zaman Pencereli Varlık Kümeleme (`IngestAlert`)**:
   - Uyarılar varlık (`EntityID`) ve kiracı (`TenantID`) bazında kayan bir zaman penceresi (`timeWindow`, örn: 1 saat) içerisinde aktif vakalarla birleştirilir.
   - Zaman penceresi dolduğunda eski vakalar kapatılır ve yeni vaka başlatılır.
2. **Çok Aşamalı Taktik Yayılımı & Eskalasyon**:
   - Vaka içerisindeki uyarılar 2 veya daha fazla farklı MITRE ATT&CK taktiğini (örn: Initial Access ve Execution) kapsadığında, kompozit ciddiyet (`CompositeSeverity`) otomatik olarak `"critical"` seviyesine yükseltilir ve eskalasyon bayrağı dönülür.
3. **Eşzamanlılık & Kiracı İzolasyonu**:
   - `sync.RWMutex` ile yüksek hacimli telemetri akışında güvenli eşzamanlı işletim.
   - Kiracı bazında tam izolasyon; farklı kiracıların uyarıları ve vakaları asla birleştirilmez.

## Sonuçlar
- Uyarı gürültüsü (alert fatigue) azaltıldı; APT saldırı zincirleri otomatik olarak tek bir kritik vakada birleştirildi.
