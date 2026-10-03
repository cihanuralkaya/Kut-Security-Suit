# ADR-0034: Chaos Engineering & Resilience Simulator (CHAOS-001 / CHAOS-005 / CHAOS-006)

## Durum
Kabul Edildi

## Bağlam
Görev-kritik güvenlik platformlarında bölgesel ağ kesintileri (Regional Failure), harici AI sağlayıcılarının çökmesi veya gecikmesi (AI Provider Outage), olay veri yolu tampon doygunlukları (Bus Saturation) ve kötü niyetli kiracıların sınır aşma saldırıları (Malicious Tenant Attacks) gibi olağanüstü durumlar kaçınılmazdır. Platformun bu tür stres koşullarında kilitlenmeden, verileri izole ederek ve zarifçe gerileyerek (graceful degradation) ayakta kaldığı doğrulanabilmelidir.

## Karar
`server/internal/coordinator` paketi altında `ChaosEngine` devreye alındı:
1. **Hata Enjeksiyon Türleri (`ChaosFaultType`)**:
   - `RegionFailure`: Belirli bir bölgedeki uç düğümleri çevrimdışı bırakarak bölgesel arıza devrini (`RegionalRouter.SetRegionStatus`) tetikler.
   - `AIProviderOutage`: Harici yapay zeka sağlayıcı kesintilerini simüle eder.
   - `BusSaturation`: Olay veri yolunu aşırı yükleyerek yük atma (drop policy) davranışını sınar.
   - `MaliciousTenantAttack`: Çapraz kiracı erişim girişimlerini simüle eder.
2. **Deney Yaşam Döngüsü & Doğrulama**:
   - `InjectFault`: Deneyi başlatır, hata parametrelerini uygular ve experiment ID üretir.
   - `HaltExperiment`: Deneyi sonlandırır ve sistemi normal çalışma durumuna döndürür.
   - `VerifyResilience`: Sistemin çökmeden, kiracı sınırlarını ihlal etmeden ve yük devrini başarıyla tamamlayarak çalıştığını teyit eder.
3. **Eşzamanlılık Güvenliği**:
   - `sync.RWMutex` ile üretim ortamı koordinatör döngüsünde güvenli eşzamanlı işletim.

## Sonuçlar
- Sistem dayanıklılığı varsayımlara bırakılmayıp kontrollü kaos enjeksiyonlarıyla sürekli test edilebilir hale getirildi.
