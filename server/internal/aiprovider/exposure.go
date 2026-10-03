package aiprovider

import (
	"context"
	"fmt"
	"time"
)

// ExposureFinding represents a discovered vulnerability or configuration issue on an asset.
type ExposureFinding struct {
	ID          string
	TenantID    string
	AssetID     string
	Kind        string // "OpenPort", "WeakCipher", "ExpiredCert", "KnownVulnerability"
	Severity    string // "Low", "Medium", "High", "Critical"
	Description string
	Remediation string
}

// RAGStore is a placeholder for the actual type if it exists in another file.
// If it's already defined, this should be removed to avoid redeclaration.
// Assuming it exists based on "existing internal packages", we just use it.
// type RAGStore struct{}

// ModelRouter is a placeholder for the actual type.
// type ModelRouter struct{}

// ExposureAgent represents the Continuous Exposure & Attack Surface Management Agent.
type ExposureAgent struct {
	// These types are assumed to be defined in the aiprovider package.
	RAGStore    *RAGStore
	ModelRouter *ModelRouter
}

// NewExposureAgent creates a new Continuous Exposure & Attack Surface Management Agent.
func NewExposureAgent(rag *RAGStore, router *ModelRouter) *ExposureAgent {
	return &ExposureAgent{
		RAGStore:    rag,
		ModelRouter: router,
	}
}

// ScanAsset evaluates an asset for exposures like open ports, expiring certs, and known vulnerable software.
func (a *ExposureAgent) ScanAsset(ctx context.Context, tenantID string, assetID string, openPorts []int, certExpiryDays int, softwareVersions map[string]string) ([]ExposureFinding, error) {
	var findings []ExposureFinding
	timestamp := time.Now().UnixNano()

	// 1. Evaluate dangerous ports
	dangerousPorts := map[int]string{
		21:   "FTP",
		23:   "Telnet",
		3389: "RDP",
		445:  "SMB",
	}

	for _, port := range openPorts {
		if service, isDangerous := dangerousPorts[port]; isDangerous {
			findings = append(findings, ExposureFinding{
				ID:          fmt.Sprintf("FINDING-%d-%s-PORT-%d", timestamp, assetID, port),
				TenantID:    tenantID,
				AssetID:     assetID,
				Kind:        "OpenPort",
				Severity:    "High",
				Description: fmt.Sprintf("Tehlikeli açık port tespit edildi: %d (%s). Dış ağa açık olması risk teşkil eder.", port, service),
				Remediation: "Bu portun dışa açık olması gerekmiyorsa firewall kuralları ile engellenmeli veya güvenli bir alternatif (örn. VPN/SSH tüneli) kullanılmalıdır.",
			})
		}
	}

	// 2. Evaluate TLS Certificates
	if certExpiryDays <= 0 {
		findings = append(findings, ExposureFinding{
			ID:          fmt.Sprintf("FINDING-%d-%s-CERT-EXPIRED", timestamp, assetID),
			TenantID:    tenantID,
			AssetID:     assetID,
			Kind:        "ExpiredCert",
			Severity:    "Critical",
			Description: "TLS sertifikası süresi dolmuş durumda.",
			Remediation: "Sertifikanın derhal yenilenmesi gerekmektedir.",
		})
	} else if certExpiryDays < 15 {
		findings = append(findings, ExposureFinding{
			ID:          fmt.Sprintf("FINDING-%d-%s-CERT-EXPIRING", timestamp, assetID),
			TenantID:    tenantID,
			AssetID:     assetID,
			Kind:        "ExpiredCert",
			Severity:    "Medium",
			Description: fmt.Sprintf("TLS sertifikasının süresinin dolmasına %d gün kaldı.", certExpiryDays),
			Remediation: "Sertifikanın yenilenme sürecinin başlatılması önerilir.",
		})
	}

	// 3. Evaluate Known Vulnerable Software
	// Mock CVE DB for known versions
	knownVulnerabilities := map[string]struct {
		VulnerableVersions []string
		Severity           string
		CVE                string
		Remediation        string
	}{
		"log4j": {
			VulnerableVersions: []string{"2.14.1", "2.14.0"},
			Severity:           "Critical",
			CVE:                "CVE-2021-44228",
			Remediation:        "Log4j sürümünü 2.15.0 veya daha yeni bir sürüme güncelleyin.",
		},
		"openssl": {
			VulnerableVersions: []string{"1.1.1k", "1.1.1l"},
			Severity:           "High",
			CVE:                "CVE-2022-0778",
			Remediation:        "OpenSSL sürümünü yamalanmış sürüme güncelleyin.",
		},
	}

	for software, version := range softwareVersions {
		if vulnData, exists := knownVulnerabilities[software]; exists {
			for _, vulnVer := range vulnData.VulnerableVersions {
				if version == vulnVer {
					findings = append(findings, ExposureFinding{
						ID:          fmt.Sprintf("FINDING-%d-%s-VULN-%s", timestamp, assetID, software),
						TenantID:    tenantID,
						AssetID:     assetID,
						Kind:        "KnownVulnerability",
						Severity:    vulnData.Severity,
						Description: fmt.Sprintf("Bilinen zafiyet tespit edildi: %s sürümü %s (%s).", software, version, vulnData.CVE),
						Remediation: vulnData.Remediation,
					})
					break // found vulnerability for this software
				}
			}
		}
	}

	return findings, nil
}
