# ADR-0039: Cryptographic Build Provenance & Attestation Engine (OSS-002)

## Durum
Kabul Edildi

## Bağlam
Saldırganlar derleme boru hatlarına (CI/CD) sızarak kaynak kodda olmayan zararlı kodları derlenmiş ikili dosyalara enjekte edebilir (örn. SolarWinds saldırısı). Platformun sürüm yapıtlarının meşru ve kurcalanmamış bir kaynak depodan ve yetkili bir derleyici (builder identity) tarafından üretildiğini kanıtlayan kriptografik yapıt kökeni (SLSA Level 3 uyumlu Provenance) gereklidir.

## Karar
`server/internal/security` paketi altında `ProvenanceVerifier` uygulandı:
1. **Derleme Köken Belgesi (`BuildProvenance`)**:
   - `BuildID`, `RepositoryURI`, `CommitSHA`, `BuilderIdentity`, `BuildTimestamp`, `ArtifactHashes` (dosya adı -> SHA256 haritası), `SLSAAttestation` ("SLSA_BUILD_LEVEL_3") ve kriptografik imza.
2. **Kriptografik Doğrulama (`VerifyArtifact`)**:
   - Dağıtılan yapıtın içeriğinin SHA-256 özetini yeniden hesaplar.
   - Provenance manifestosunda kayıtlı hash ile eşleştiğini doğrular; değiştirilmiş dosyalarda derhal ihlal döner.
3. **Eşzamanlılık Güvenliği**:
   - `sync.Mutex` ile güvenli iş parçacığı yönetimi.

## Sonuçlar
- KUT platformu derleme ve dağıtım zincirinde SLSA Seviye 3 güvencesi sağlayarak tedarik zinciri saldırılarına karşı korunmuştur.
