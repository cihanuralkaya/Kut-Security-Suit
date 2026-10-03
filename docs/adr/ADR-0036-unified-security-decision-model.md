# ADR-0036: Unified Security Decision Model & Attestation Hashing (ARCH-007)

## Durum
Kabul Edildi

## Bağlam
Kontrol düzleminde yürütülen operasyonel kararlar (izin verme, engelleme, iki kişilik onay gereksinimi, karantina) parçalı kontroller yerine tek, birleşik ve kriptografik olarak kanıtlanabilir (provable/attested) bir karar modeline dayanmalıdır. Kararın sonradan değiştirilememesi ve denetim kayıtlarıyla tam örtüşmesi için karar anında kriptografik onay özeti (Attestation Hash) hesaplanmalıdır.

## Karar
`server/internal/controlplane` paketinde `DecisionEngine` uygulandı:
1. **Güvenlik Bağlamı (`SecurityContext`)**:
   - `TenantID`, `ActorID`, `ActorRole`, `SourceDeviceID`, `TargetDeviceID`, `ActionName`, `ActionImpact` ("read", "write", "destructive"), `RiskScore` (0.0 to 1.0) ve `Confidence`.
2. **Karar Çıktısı & Politika Değerlendirmesi (`DecisionOutcome`)**:
   - `Permit`: Düşük riskli ve yetkili işlemler.
   - `Deny`: Geçersiz kiracı, yetkisiz aktör veya kapsam dışı etkiler.
   - `Challenge`: Risk skoru > 0.7 olan yıkıcı operasyonlar (`RequiresDualAuth = true` bayrağı ile çift yetki onayı zorunlu kılınır).
   - `Quarantine`: Sistem güvenliğini tehdit eden kontrolsüz aktörler.
3. **Kriptografik Onay Özeti (`AttestationHash`)**:
   - Karar nesnesi ve bağlamının SHA-256 kanonik özeti hesaplanarak `SecurityDecision` içine mühürlenir. Bu özet, denetim günlüğü (`audit_log`) ve adli zincir ile çapraz doğrulanabilir.

## Sonuçlar
- Kontrol düzlemi kararları deterministik kurallarla standartlaştırıldı ve inkâr edilemez kriptografik mühürleme sağlandı.
