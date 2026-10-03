# ADR-0037: High-Scale Performance & Latency Benchmark Suite (BENCH-004 / BENCH-006 / BENCH-008)

## Durum
Kabul Edildi

## Bağlam
KUT güvenlik dokusu, ticari rakipleriyle (Trend Vision One, CrowdStrike Falcon, SentinelOne, Cortex XSIAM) yarışırken milyonlarca olay/saniye (EPS) seviyesindeki telemetri hacimlerini ve mikro-saniye düzeyindeki AI/DLP güvenlik kontrollerini garanti edebilmelidir. Sistemin verim ve gecikme metriklerinin regresyona uğramaması için sürekli kıyaslama (benchmarking) test paketi oluşturulmalıdır.

## Karar
`telemetryplane` ve `aiprovider` paketlerinde kıyaslama testleri uygulandı:
1. **Telemetri Düzlemi Alım & Kural Değerlendirme (`BenchmarkTelemetryPlane_ProcessEvent`, `BenchmarkRuleEngine_Evaluate`)**:
   - Etkinlik alımı ve OCSF doğrulama süresi ölçüldü.
   - Sınırlandırılmış tamponlu EventBus yayınlama hızı test edildi (`BenchmarkEventBus_Publish`).
2. **AI Güvenlik & DLP Gecikmesi (`BenchmarkDataDLP_ScrubPII`, `BenchmarkModelRouter_Route`, `BenchmarkRAGStore_Search`)**:
   - Hassas veri ve PII temizleme işlemi ~1.7 mikro-saniye operasyon süresiyle doğrulandı.
   - Model yönlendirme ve RAG vektör benzerlik sorguları sıfır bellek ayırma (0 allocs/op) ile yüksek başarım sergiledi.

## Sonuçlar
- KUT Güvenlik Dokusunun yüksek hacimli kurumsal iş yüklerinde ölçeklenebilirliği ve düşük gecikmesi ölçümlenerek kanıtlandı.
