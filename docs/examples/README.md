# Tespit Kuralı Örnekleri / Detection Rule Examples

`detection-rules.sample.json`, KUT tespit motorunun (IDS-esinli) gelişmiş
kural alanlarını gösteren, çalışır ve CI ile doğrulanan örneklerdir. Motora şu
ortam değişkeniyle yüklenir:

```bash
export KUT_DETECT_RULES_FILE=/path/to/detection-rules.sample.json
# (opsiyonel) imza zorunluluğu için:
export KUT_DETECT_RULES_PUBKEY=<base64 Ed25519 açık anahtar>
```

Özel kurallar yerleşik varsayılanlara EKLENİR (varsayılanların davranışı değişmez).

## Kural alanları / Rule fields

Temel: `id`, `name`, `severity` (INFO|LOW|MEDIUM|HIGH|CRITICAL) zorunlu; `category`,
`technique`, `status` (draft|active|retired), `author`, `version`, `references` opsiyonel.

Eşleşme koşulları (hepsi AND'lenir):

| Alan | Anlam | IDS karşılığı |
|------|-------|--------------------|
| `contains` | Mesajda geçmesi gereken alt-dizeler (sırasız, duyarsız) | `content` |
| `absent` | Mesajda geçMEmesi gereken alt-dizeler (dışlama) | `content:!"..."` |
| `sequence` | Verilen SIRAYLA geçmesi gereken literaller | `content` + `distance` |
| `within_bytes` | Ardışık `sequence` eşleşmeleri arası en fazla bayt | `within` |
| `message_regex` | Mesaj bu regex'e uymalı (duyarsız) | `pcre` |
| `fields` | `details` JSON'unda alan→alt-dize eşleşmesi | app-layer buffers |
| `min_severity` | Olayın en az bu önemde olması | — |

Alarm/durum katmanı (opsiyonel):

| Alan | Anlam | IDS karşılığı |
|------|-------|--------------------|
| `threshold` `{count, seconds, track}` | Pencerede EN AZ `count` kez görülmeden alarm ÜRETİLMEZ (brute-force/tarama). `track`: device\|tenant\|global | `threshold` / `detection_filter` |
| `bits` `{require, require_not, set, ttl_seconds, track}` | Çok-aşamalı tespit: `require` bitleri kuruluyken VE `require_not` bitleri kurulu DEĞİLKEN alarma izin; eşleşince `set` bitleri kurulur (TTL'li) | `flowbits:isset` / `isnotset` / `set` |

### Örnek: çok-aşamalı (bits)

`KUT-EX-0010` iç-ağ keşfinde `recon_seen` bitini 1 saatliğine kurar. `KUT-EX-0011`
(kimlik dökümü) yalnız `recon_seen` kuruluyken CRITICAL alarma dönüşür — tek başına
görülen kimlik-dökümü sinyali, öncesinde keşif olmadıkça bu kuralca yükseltilmez.

Bu örnek dosya `TestExampleRulesValid` ile her derlemede doğrulanır; şema
geliştikçe örnekler geçerli kalır.
