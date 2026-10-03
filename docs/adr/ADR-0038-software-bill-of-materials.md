# ADR-0038: Software Bill of Materials (SBOM) & Component Integrity (OSS-001)

## Durum
Kabul Edildi

## Bağlam
Modern açık kaynak ve egemen güvenlik platformlarında yazılım tedarik zinciri güvenliği (Supply Chain Security) en temel gereksinimdir. Platformu oluşturan tüm bileşenlerin (kütüphaneler, çerçeveler, modeller, ikililer) listesi, lisansları, PURL tanımlayıcıları ve kriptografik özetleri makine tarafından okunabilir formatta (CycloneDX / SPDX) belgelenmeli ve tahrifat denetimi yapılabilmelidir.

## Karar
`server/internal/security` paketi altında `SBOMGenerator` devreye alındı:
1. **Bileşen Modeli (`SBOMComponent`)**:
   - İsim, sürüm, tür (`library`, `framework`, `binary`, `model`, `tool`), lisans (Apache-2.0, MIT), PURL ve SHA-256 sağlama toplamı.
2. **SBOM Belgesi Üretimi (`GenerateKutSBOM`)**:
   - CycloneDX 1.5 ve SPDX 2.3 standartlarıyla uyumlu belge şeması (`SBOMDocument`).
   - JSON formatında dışa aktarma (`ExportJSON`).
3. **Bileşen Doğrulama & Tahrifat Koruması (`VerifyComponentChecksum`)**:
   - Dağıtılan veya yüklenen ikililerin/modellerin gerçek içerik özetini SBOM kaydıyla karşılaştırarak tahrifatı saptar.

## Sonuçlar
- KUT platformu tam şeffaflıkla denetlenebilir ve kurumsal güvenlik uyumluluk standartlarına (NIST, OpenSSF) hazır hale getirildi.
