# ADR-0028: High-Throughput In-Memory Event Bus (SCALE-001)

## Durum
Kabul Edildi

## Bağlam
Milyonlarca uç nokta telemetrisinin (Process, Network, DNS, File) eşzamanlı olarak tespit motorlarına, AI ajanlarına ve adli tıp kaydedicilerine dağıtılması gerekmektedir. Yavaş bir abonenin tüm telemetri boru hattını kilitlemesini (head-of-line blocking) önlemek ve çok-kiracılı konu izolasyonunu sağlamak için sınırlandırılmış tampon (bounded buffer) ve yük atma (drop/shedding) politikasına sahip yüksek verimli bir Event Bus gereklidir.

## Karar
`server/internal/telemetryplane` paketinde `EventBus` mimarisi uygulandı:
1. **Yayın / Dinleme Modeli (`Publish` / `Subscribe`)**:
   - `BusEvent`: `ID`, `Topic`, `TenantID`, `Payload`, `Timestamp`.
   - `Subscriber`: Sınırlandırılmış kanala (`chan BusEvent`, `bufSize`) sahip abonedir.
2. **Taşma ve Yük Atma Politikası (Drop Policy)**:
   - Abone tamponu dolduğunda `select default` yapısıyla engellenmeden (non-blocking) olay atılır; diğer abonelerin ve telemetri düzleminin gecikmesi korunur.
3. **Konu Eşleme & Kiracı İzolasyonu**:
   - Konu deseni önek (`*` joker) veya tam eşleşme destekler.
   - Kiracı bazında izolasyon: aboneler yalnız kendi kiracılarına ait veya platform geneli (`*`) olayları dinleyebilir.
4. **Eşzamanlılık ve Yaşam Döngüsü**:
   - `sync.RWMutex` ile thread-safe abone yönetimi.
   - `Unsubscribe` ve `Close` ile kaynak sızıntısı önlenir.

## Sonuçlar
- Telemetri dağıtımı kilitlenmesiz ve izole hale getirildi. Yüksek hacimli akışlar altında backpressure koruması sağlandı.
