# ADR-0035: Model Registry & Local Heuristic Fallback Engine (AI-007 / AI-009)

## Durum
Kabul Edildi

## Bağlam
KUT güvenlik dokusunda çalışan otonom ajanlar (araştırmacı, avcı, müdahale) farklı model yeteneklerine (triage, hunting, investigation, code_analysis) ihtiyaç duyar. Ayrıca harici AI sağlayıcılarının (OpenAI, Anthropic vb.) ağ kesintisi veya kota aşımı yaşaması durumunda tüm güvenlik platformunun körleşmesini önlemek için deterministik ve yerel çalışan bir yedek sınıflandırıcı mekanizması (offline heuristic fallback) şarttır.

## Karar
`server/internal/aiprovider` paketi altında `ModelRegistry` ve `LocalHeuristicClassifier` devreye alındı:
1. **Model Kayıt Defteri (`ModelRegistry`)**:
   - `ModelMetadata`: Model kimliği, sağlayıcı adı, yetenek listesi (`ModelCapability`), yerel/uzak durumu (`IsLocal`), token sınırı, gecikme süresi (`LatencyMs`) ve sağlık durumu (`Healthy`).
   - `SelectBestModel`: İstenen yeteneğe sahip en sağlıklı ve düşük gecikmeli modeli seçer. `preferLocal = true` olduğunda veya tüm harici modeller çevrimdışı olduğunda yerel modelleri önceler.
   - `UpdateHealth`: Sağlık ve gecikme metriklerini dinamik olarak günceller.
2. **Yerel Sezgisel Sınıflandırıcı (`LocalHeuristicClassifier`)**:
   - Dış ağa veya API anahtarına ihtiyaç duymaksızın çalışan çevrimdışı güvenlik sınıflandırıcısıdır.
   - Bilinen saldırı göstergelerini, kabuk betiklerini ve hassas parametreleri deterministik regex ve kural mantığıyla puanlar.

## Sonuçlar
- Harici yapay zeka sağlayıcılarına bağımlılık azaltıldı; sıfır internet veya sağlayıcı çökmesi durumunda dahi yerel sınıflandırıcı ile platform işlevselliği sürdürülür.
