package aiprovider

import (
	"regexp"
	"strings"
)

// DataClassifier inspects prompts, telemetry details, and agent messages to assign a Sensitivity level.
type DataClassifier struct {
	restrictedRules   []*regexp.Regexp
	confidentialRules []*regexp.Regexp
}

// NewDataClassifier DataClassifier nesnesini oluşturur.
func NewDataClassifier() *DataClassifier {
	return &DataClassifier{
		restrictedRules: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(password|secret|credential)\s*[:=]\s*\S+`),
			regexp.MustCompile(`(?i)BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY`),
			regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), // AWS Access Key pattern (indicator for secrets)
			regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), // SSN
			regexp.MustCompile(`\b[1-9]\d{10}\b`),       // TCKN
			// Sovereign internal IPs
			regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
			regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`),
			regexp.MustCompile(`\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b`),
		},
		confidentialRules: []*regexp.Regexp{
			regexp.MustCompile(`(?i)incident details?`),
			regexp.MustCompile(`(?i)\b[a-z0-9-]+\.internal\b`),
			regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), // User email
		},
	}
}

// ClassifyText assigns a Sensitivity level to the given text based on classification rules.
func (c *DataClassifier) ClassifyText(text string) Sensitivity {
	for _, rule := range c.restrictedRules {
		if rule.MatchString(text) {
			return Restricted
		}
	}

	for _, rule := range c.confidentialRules {
		if rule.MatchString(text) {
			return Confidential
		}
	}

	lower := strings.ToLower(text)
	if strings.Contains(lower, "metric") || strings.Contains(lower, "error log") || strings.Contains(lower, "telemetry") {
		return Internal
	}

	return Public
}

// ClassifyEvent assigns a Sensitivity level based on event properties and details.
func (c *DataClassifier) ClassifyEvent(category, severity, details string) Sensitivity {
	baseSensitivity := c.ClassifyText(details)
	
	// Kritik auth hatalarını Restricted / Confidential seviyesine yükselt
	if strings.Contains(strings.ToLower(category), "auth") && strings.ToLower(severity) == "critical" {
		if baseSensitivity == Public || baseSensitivity == Internal {
			return Restricted
		}
	}
	
	return baseSensitivity
}
