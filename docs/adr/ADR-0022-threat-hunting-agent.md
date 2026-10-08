# ADR-0022: Autonomous Threat Hunting Agent (AGENT-002)

## Durum
Kabul Edildi

## Bağlam
XDR platformlarında reaktif tespitler (alert-driven) saldırganların sessizce yerleştiği "dwell time" sürecinde yetersiz kalmaktadır. Tehdit avcılığı (threat hunting), henüz tespit kuralı tetiklenmemiş gizli anomalileri, nadir ilişkileri (rare connections) ve saldırgan tekniklerini proaktif olarak aramak zorundadır.

## Karar
`server/internal/aiprovider` paketi altında `HuntingAgent` mimarisi kuruldu:
1. **Hipotez Üretimi (`HuntHypothesis`)**: MITRE ATT&CK taktik ve tekniklerine (örn: Execution, T1059) dayalı hedefli av hipotezleri üretir.
2. **Graf Taraması (`ExecuteHunt`)**: `entitygraph.Graph` üzerinde hedef varlık türündeki (örn: Process) düğümleri ve kenarları analiz eder.
3. **Nadir İlişki & Anomali Puanlama (`HuntFinding`)**: Kenarların gözlem sıklığına (observation count threshold <= 2) göre nadir/şüpheli ilişkileri tespit eder ve risk skoru ile özet üretir.
4. **Çok-Kiracılı İzolasyon**: Tüm graf ve av operasyonları çağıran kiracı bağlamına sıkı sıkıya bağlıdır.

## Sonuçlar
- Proaktif tehdit avcılığı otonom hale getirilerek kuralların yakalayamadığı nadir ve gizli anomaliler graf düzeyinde saptanır.
- RAG bilgi tabanı ve model yönlendirici ile entegre edilebilir bir altyapı oluşturuldu.
