package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReadyzPartitionGate, /readyz'in olay-partition hazırlığını kapı olarak
// kullandığını doğrular: partition yoksa depo erişilebilir olsa bile 503.
func TestReadyzPartitionGate(t *testing.T) {
	srv, _ := newServer(t)
	srv.SetHealthCheck(func(context.Context) error { return nil }) // depo erişilebilir
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Partition hazır DEĞİL → 503.
	srv.SetPartitionReadiness(func(context.Context) (bool, error) { return false, nil })
	if code := getCode(t, ts.URL+"/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("partition yokken /readyz = %d, 503 beklendi", code)
	}

	// Partition hazır → 200.
	srv.SetPartitionReadiness(func(context.Context) (bool, error) { return true, nil })
	if code := getCode(t, ts.URL+"/readyz"); code != http.StatusOK {
		t.Fatalf("partition hazırken /readyz = %d, 200 beklendi", code)
	}

	// Kontrol ayarlı değil (memstore) → yalnız depo sağlığına bakar → 200.
	srv.SetPartitionReadiness(nil)
	if code := getCode(t, ts.URL+"/readyz"); code != http.StatusOK {
		t.Fatalf("partition kontrolü yokken /readyz = %d, 200 beklendi", code)
	}
}

func getCode(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
