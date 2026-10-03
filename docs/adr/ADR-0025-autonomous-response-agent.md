# ADR-0025: Autonomous Incident Response Agent & Two-Person Approval Gate (AGENT-006)

## Durum
Kabul Edildi

## Bağlam
XDR platformlarında otonom müdahale (containment/remediation) operasyonları (uç nokta izolasyonu, oturum iptali, hash bloklama, dosya karantinası, süreç sonlandırma) kritik risk taşır. Yanlış pozitif sonucu bir domain controller veya kritik veri tabanının izole edilmesi kurumsal kesintiye yol açabilir. Bu nedenle müdahale eylemleri risk sınıflarına göre derecelendirilmeli ve yıkıcı eylemler için insan onay kapısı (Two-Person Rule / Human-in-the-Loop) zorunlu tutulmalıdır.

## Karar
`server/internal/aiprovider` paketi altında `ResponseAgent` uygulandı:
1. **Müdahale Planlama (`ProposePlan`)**:
   - `HuntFinding` bulguları ve vaka ciddiyetine (Severity) göre eylem planı (`ResponsePlan`) oluşturur.
   - Kritik ciddiyetteki vakalarda anında çevreleme (containment) aksiyonları planlar.
   - Yıkıcı veya yüksek etkili aksiyonlar (`IsolateEndpoint`, `KillProcess`) için `RequiresApproval = true` işaretler.
2. **Onay & İcra Kapısı (`ExecuteAction`)**:
   - `RequiresApproval = true` olan aksiyonlar geçerli bir onaylayan (`approver`) kimliği olmadan icra edilemez; fail-closed kuralı uygulanır.
   - Onaylandığında yürütme zamanı (`ExecutedAt`) ve onay durumu güncellenir.
3. **Kiracı İzolasyonu**:
   - Her müdahale aksiyonu ve planı `TenantID` alanına bağlıdır; çapraz kiracı müdahalesi kesin olarak engellenir.

## Sonuçlar
- Otonom vaka müdahalesi güvenli hale getirildi; kritik iş süreçlerinin yapay zeka tarafından yanlışlıkla kesintiye uğratılması önlendi.
