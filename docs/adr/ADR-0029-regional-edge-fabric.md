# ADR-0029: Regional Edge Fabric & Routing (ARCH-002)

## Durum
Kabul Edildi

## Bağlam
Küresel kurumsal dağıtımlarda uç nokta telemetrisinin tek bir merkezi veri merkezine gönderilmesi yüksek ağ gecikmesine ve veri egemenliği (data sovereignty) uyumsuzluklarına yol açar. Telemetrinin coğrafi olarak en yakın bölgesel uç düğümlere (edge nodes) yönlendirilmesi, düğüm arızalarında ise otomatik yük devri (failover) yapılması zorunludur.

## Karar
`server/internal/coordinator` paketi altında `RegionalRouter` uygulandı:
1. **Uç Düğüm Yönetimi (`EdgeNode`)**:
   - `RegionID` (örn: `eu-central-1`, `us-east-1`, `tr-marmara-1`).
   - Durum takibi (`healthy`, `degraded`, `offline`), son kalp atışı (`LastHeartbeat`) ve ağ gecikmesi (`LatencyMs`).
2. **Gecikme & Bölge Odaklı Yönlendirme (`RouteTelemetry`)**:
   - Kiracının birincil bölgesindeki en düşük gecikmeli sağlıklı düğüm seçilir.
   - Birincil bölgede aktif düğüm kalmadığında, en yakın alternatif bölgedeki sağlıklı düğüme otomatik arıza devri (failover) yapılır.
3. **Eski/Cevapsız Düğümleri Temizleme (`PruneStaleNodes`)**:
   - Belirlenen eşik süresi boyunca kalp atışı göndermeyen düğümler sistemden otomatik ayıklanır.

## Sonuçlar
- Çok bölgeli dağıtımlarda telemetri gecikmesi asgari düzeye indirildi ve uç düğüm arızalarına karşı otomatik dayanıklılık sağlandı.
