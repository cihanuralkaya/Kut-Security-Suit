package connectors

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"kut.corp/suite/server/internal/connector"
)

// config.go — connector'ların YAPILANDIRMADAN kurulması (§29/§30 canlı hatta bağlama).
// Bir JSON dosyası kaynak listesini tanımlar; her giriş bir connector.Connector'a
// dönüştürülür. Böylece operatör, kod değiştirmeden yeni log/bulut kaynağı ekleyebilir.

// SourceConfig, tek bir bağlayıcı kaynağının yapılandırmasıdır.
type SourceConfig struct {
	Name        string `json:"name"`               // benzersiz bağlayıcı adı
	Format      string `json:"format"`             // syslog|cef|leef|json|winevent|cloud
	Source      string `json:"source"`             // yerel dosya yolu (çevrimdışı puller)
	Provider    string `json:"provider,omitempty"` // cloud için: aws|azure|gcp|m365
	Whole       bool   `json:"whole,omitempty"`    // belge-tabanlı formatlar (json/winevent/cloud) → true
	IntervalSec int    `json:"interval_sec"`       // yoklama aralığı (sn); <=0 → 60
}

// Interval, yapılandırılan yoklama aralığını döner (varsayılan 60sn).
func (c SourceConfig) Interval() time.Duration {
	if c.IntervalSec <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.IntervalSec) * time.Second
}

// Build, bir SourceConfig'i somut bir connector.Connector'a dönüştürür. Kaynak yerel
// dosyadır (FilePuller); belge-tabanlı formatlar için whole=true tüm dosyayı tek kayıt
// olarak okur. Bilinmeyen format → hata.
func Build(c SourceConfig) (connector.Connector, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("connectors: ad boş olamaz")
	}
	if c.Source == "" {
		return nil, fmt.Errorf("connectors: %q kaynağı boş", c.Name)
	}
	pull := FilePuller(c.Source, c.Whole)
	switch c.Format {
	case "syslog":
		return NewSyslogConnector(c.Name, pull), nil
	case "cef":
		return NewCEFConnector(c.Name, pull), nil
	case "leef":
		return NewLogConnector(c.Name, "siem", pull, LEEFNormalizer, nil), nil
	case "json":
		return NewLogConnector(c.Name, "endpoint", FilePuller(c.Source, true), JSONNormalizer, nil), nil
	case "winevent":
		return NewWinEventConnector(c.Name, FilePuller(c.Source, true)), nil
	case "cloud":
		return NewCloudConnector(c.Name, c.Provider, FilePuller(c.Source, true)), nil
	default:
		return nil, fmt.Errorf("connectors: %q bilinmeyen format %q", c.Name, c.Format)
	}
}

// LoadConfig, bir JSON dosyasından kaynak listesini okur. Dosya bir SourceConfig
// dizisidir. Boş/eksik dosya → hata.
func LoadConfig(path string) ([]SourceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []SourceConfig
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("connectors: yapılandırma çözülemedi: %w", err)
	}
	return out, nil
}

// BuildAll, yapılandırma listesinden bir Registry kurar. İlk hatalı giriş hatayı
// döndürür (fail-fast; yanlış yapılandırma sessizce yutulmaz).
func BuildAll(cfgs []SourceConfig) (*connector.Registry, error) {
	reg := connector.NewRegistry()
	for _, c := range cfgs {
		conn, err := Build(c)
		if err != nil {
			return nil, err
		}
		if err := reg.Register(conn); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
