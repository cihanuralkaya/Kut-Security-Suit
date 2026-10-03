# ADR-0033: Live Forensics Evidence Artifact Collector (DFIR-001)

## Durum
Kabul Edildi

## Bağlam
Aktif bir saldırı sırasında veya hemen sonrasında uç noktalardan toplanan canlı adli kanıtlar (süreç ağacı, açık ağ soketleri, bellek metadataları, disk artıkları) mahkemede kabul edilebilir (court-admissible) ve tahrifata karşı dayanıklı olmak zorundadır. Kanıtın toplanma anındaki kriptografik özeti çıkarılmalı ve kiracı sınırları içinde mühürlenmelidir.

## Karar
`server/internal/evidence` paketinde `EvidenceCollector` uygulandı:
1. **Canlı Kanıt Modeli (`LiveArtifact`)**:
   - `ArtifactKind`: `ProcessTree`, `NetworkSockets`, `MemoryMetadata`, `DiskArtifact`.
   - `SHA256Hash`: İçeriğin (`RawContent`) kriptografik SHA-256 özeti.
   - `CollectorSignature`: Toplayıcı düğümün doğrulama imzası.
2. **Kriptografik Bütünlük & Tahrifat Koruması**:
   - `CollectArtifact`: Toplama anında hash otomatik hesaplanır, benzersiz ID atanır, boş içerik veya kiracısız çağrılar reddedilir.
   - `VerifyArtifactIntegrity`: Kanıt içeriğinin bayt düzeyinde değiştirilip değiştirilmediğini anında doğrular; 1 baytlık sapmada bile bütünlük doğrulaması başarısız olur.
3. **Zaman Tüneli & İnkâr Edilemezlik Entegrasyonu**:
   - Toplanan kanıtlar `evidence.ChainOfCustody` ve `evidence.Timeline` bileşenleriyle tam uyumludur.

## Sonuçlar
- Canlı adli kanıtlar kriptografik bütünlük güvencesiyle toplanır ve tahrifata karşı korunur.
