package aiprovider

import (
	"context"
	"testing"
)

func TestExposureAgent_ScanAsset(t *testing.T) {
	// Create an agent instance
	agent := NewExposureAgent(nil, nil)
	ctx := context.Background()

	t.Run("Clean Asset", func(t *testing.T) {
		findings, err := agent.ScanAsset(ctx, "tenant-1", "asset-1", []int{80, 443}, 30, map[string]string{
			"nginx": "1.21.0",
		})

		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("temiz bir varlık için 0 bulgu bekleniyordu, ancak %d bulundu", len(findings))
		}
	})

	t.Run("Dangerous Ports", func(t *testing.T) {
		findings, err := agent.ScanAsset(ctx, "tenant-1", "asset-2", []int{21, 23, 3389, 445, 80}, 60, nil)
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}

		if len(findings) != 4 {
			t.Errorf("4 tehlikeli port bulgusu bekleniyordu, %d bulundu", len(findings))
		}

		for _, f := range findings {
			if f.Kind != "OpenPort" {
				t.Errorf("bulgu türü OpenPort bekleniyordu, %s bulundu", f.Kind)
			}
			if f.TenantID != "tenant-1" || f.AssetID != "asset-2" {
				t.Errorf("yanlış tenant veya asset id")
			}
		}
	})

	t.Run("Expiring Certificates", func(t *testing.T) {
		findings, err := agent.ScanAsset(ctx, "tenant-2", "asset-3", nil, 10, nil)
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}

		if len(findings) != 1 {
			t.Fatalf("1 süresi dolmak üzere sertifika bulgusu bekleniyordu, %d bulundu", len(findings))
		}

		if findings[0].Severity != "Medium" {
			t.Errorf("beklenen önem derecesi Medium, bulundu %s", findings[0].Severity)
		}

		findingsExpired, _ := agent.ScanAsset(ctx, "tenant-2", "asset-4", nil, 0, nil)
		if len(findingsExpired) != 1 || findingsExpired[0].Severity != "Critical" {
			t.Errorf("süresi dolmuş sertifika için Critical bulgu bekleniyordu")
		}
	})

	t.Run("Known Vulnerable Software", func(t *testing.T) {
		findings, err := agent.ScanAsset(ctx, "tenant-1", "asset-5", nil, 100, map[string]string{
			"log4j":   "2.14.1",
			"openssl": "1.1.1k",
			"nginx":   "1.21.0", // safe
		})
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}

		if len(findings) != 2 {
			t.Fatalf("2 zafiyet bulgusu bekleniyordu, %d bulundu", len(findings))
		}
	})

	t.Run("Tenant Binding and All Issue Mix", func(t *testing.T) {
		findings, err := agent.ScanAsset(ctx, "tenant-x", "asset-x", []int{3389}, -5, map[string]string{
			"log4j": "2.14.0",
		})
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}

		if len(findings) != 3 {
			t.Fatalf("3 bulgu bekleniyordu, %d bulundu", len(findings))
		}

		for _, f := range findings {
			if f.TenantID != "tenant-x" || f.AssetID != "asset-x" {
				t.Errorf("bulgular doğru tenant ve asset ile ilişkilendirilmemiş")
			}
		}
	})
}
