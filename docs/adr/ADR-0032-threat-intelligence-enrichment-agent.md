# ADR-0032: Threat Intelligence & IOC Enrichment Agent (AGENT-005)

## Durum
Kabul Edildi

## Bağlam
Telemetri akışında ve güvenlik olaylarında gözlemlenen IP'ler, alan adları, dosya özetleri (SHA-256) ve URL'ler harici tehdit istihbaratı ile anında zenginleştirilmelidir. Zenginleştirme süreci olmadan güvenlik analistleri ve AI araştırmacı ajanları gözlemlenen bir IP'nin bilinen bir APT C2 sunucusuna mı yoksa meşru bir CDN'e mi ait olduğunu kestiremez.

## Karar
`server/internal/aiprovider` paketi altında `ThreatIntelAgent` uygulandı:
1. **Çok Türlü Tehdit Göstergesi Modeli (`ThreatIndicator`)**:
   - `IOCType`: IPv4, Domain, SHA-256, URL.
   - Tehdit aktörü (`ThreatActor`), zararlı ailesi (`MalwareFamily`), güven skoru (`ConfidenceScore`), etiketler ve zaman damgaları.
2. **Hızlı IOC Zenginleştirme (`EnrichIOC` / `BulkEnrich`)**:
   - Eşzamanlı okumalara optimize (`sync.RWMutex`) in-memory gösterge tablosu.
   - Bilinen kötü niyetlilik durumu (`IsKnownMalicious`), itibar skoru (`ReputationScore` 0.0 - 1.0) ve eşleşen aktör/aile listeleri döner.
   - Çoklu göstergeler için tek seferde `BulkEnrich` desteği.

## Sonuçlar
- Telemetri ve vaka analizlerinde IOC itibar sorguları yerel, güvenli ve mikro-saniye mertebesinde tamamlanır.
