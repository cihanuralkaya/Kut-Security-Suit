# ADR-0023: Real-Time Entity Resolution Engine (XDR-002)

## Durum
Kabul Edildi

## Bağlam
Kurumsal ağlarda uç noktalar ve kullanıcılar sürekli dinamik değişkenlere sahiptir (DHCP IP kira süreleri, VPN bağlantıları, farklı formatlarda gelen kullanıcı kimlikleri örn. `CORP\john.doe` vs `john.doe@corp.local`). Ham IP veya kullanıcı adı üzerinden korelasyon yapıldığında DHCP IP değişimi durumunda yanlış pozitif saldırı zincirleri oluşmaktadır.

## Karar
`server/internal/entitygraph` paketinde `EntityResolver` uygulandı:
1. **Dinamik Donanım & IP Çözümleme (`ResolveDevice`)**:
   - Güçlü tanımlayıcılar (MAC adresi, hostname) önceliklidir.
   - Zaman damgalı DHCP kiralama haritası (`ipLeases`) ile yalnız IP belirtilen olaylar doğru zaman aralığındaki cihaza bağlanır.
   - Yeni bir MAC adresi aynı IP'yi talep ettiğinde DHCP kira değişimi algılanır ve yeni bir kanonik cihaz düğümü açılır; eski cihaz ile IP bağı güncellenir.
2. **Kullanıcı Normalizasyonu (`ResolveUser`)**:
   - `DOMAIN\user`, `user@domain`, veya salt e-posta formatları tek bir kanonik `User` düğümüne dönüştürülür.
3. **Eşzamanlılık & Kiracı İzolasyonu**:
   - `sync.RWMutex` ile thread-safe kiralama ve haritalama yönetilir.
   - Kiracı bazında (`tenantID`) ayrık çözümleme tabloları tutulur; kiracılar arası IP çakışmaları izole edilir.

## Sonuçlar
- Ağ telemetrisi ve uç nokta olayları değişken IP'lere rağmen kalıcı donanım ve kimliklerle tutarlı bir şekilde ilişkilendirilir.
