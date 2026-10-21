package adminapi

// Bu dosya, "Kiracı Duvarı I" dilimine ait saf (test edilebilir) yardımcıları içerir:
// kiracı sunucu-tarafı oturumdan çözülür, istemci gövdesinden ASLA güvenilmez.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/tenant"
)

// resolveTokenTenant, enrollment token'ın mühürleneceği kiracıyı çözer.
//
//   - Kiracıya bağlı çağıran (callerTenant != ""): HER ZAMAN kendi kiracısı. Gövdedeki
//     değer boşsa "kendi kiracım"dır (asla dağıtım varsayılanı değil); kendi kiracısıyla
//     (normalize edilmiş) AYNI değilse admin.ErrForbidden — başka kiracıya cihaz sokma yok.
//   - Platform admini (callerTenant == ""): gövde boşsa dağıtım varsayılanı; doluysa
//     tenant.Normalize ile doğrulanmış kiracı (geçersiz → admin.ErrInvalidInput).
func resolveTokenTenant(callerTenant, requested, deploymentDefault string) (string, error) {
	requested = strings.TrimSpace(requested)
	if callerTenant != "" {
		if requested != "" {
			n, err := tenant.Normalize(requested)
			if requested != callerTenant && (err != nil || string(n) != callerTenant) {
				return "", admin.ErrForbidden
			}
		}
		return callerTenant, nil
	}
	if requested == "" {
		return deploymentDefault, nil
	}
	n, err := tenant.Normalize(requested)
	if err != nil {
		return "", admin.ErrInvalidInput
	}
	return string(n), nil
}

// decodeOptional, İSTEĞE BAĞLI JSON gövdesini (boş gövde tolere edilir) boyut sınırıyla
// çözer. Bozuk JSON / aşırı büyük gövde için hata yanıtı yazar ve false döner.
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "istek gövdesi çok büyük")
			return false
		}
		writeErr(w, http.StatusBadRequest, "geçersiz JSON")
		return false
	}
	return true
}
