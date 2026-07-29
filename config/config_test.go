package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestLoad(t *testing.T) {
	content := `
vuls_server:
  url: "https://vuls.example.com"
  timeout: 45s
  cert_file: "/etc/ssl/cert.pem"
  key_file: "/etc/ssl/key.pem"
  ca_file: "/etc/ssl/ca.pem"
listen_address: "127.0.0.1:9090"
scan_interval: 6h
upstream_retry_delay: 90m
`
	path := writeTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.VulsServer.URL != "https://vuls.example.com" {
		t.Errorf("expected URL https://vuls.example.com, got %s", cfg.VulsServer.URL)
	}
	if cfg.VulsServer.Timeout.Duration != 45*time.Second {
		t.Errorf("expected timeout 45s, got %s", cfg.VulsServer.Timeout.Duration)
	}
	if cfg.VulsServer.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("expected cert_file /etc/ssl/cert.pem, got %s", cfg.VulsServer.CertFile)
	}
	if cfg.VulsServer.KeyFile != "/etc/ssl/key.pem" {
		t.Errorf("expected key_file /etc/ssl/key.pem, got %s", cfg.VulsServer.KeyFile)
	}
	if cfg.VulsServer.CAFile != "/etc/ssl/ca.pem" {
		t.Errorf("expected ca_file /etc/ssl/ca.pem, got %s", cfg.VulsServer.CAFile)
	}
	if cfg.ListenAddress != "127.0.0.1:9090" {
		t.Errorf("expected listen_address 127.0.0.1:9090, got %s", cfg.ListenAddress)
	}
	if cfg.ScanInterval.Duration != 6*time.Hour {
		t.Errorf("expected scan_interval 6h, got %s", cfg.ScanInterval.Duration)
	}
	if cfg.UpstreamRetryDelay.Duration != 90*time.Minute {
		t.Errorf("expected upstream_retry_delay 90m, got %s", cfg.UpstreamRetryDelay.Duration)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "{{invalid yaml")

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_InvalidDuration(t *testing.T) {
	content := `
vuls_server:
  url: "https://example.com"
  timeout: "not-a-duration"
listen_address: "127.0.0.1:9090"
scan_interval: 1h
`
	path := writeTempConfig(t, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLoad_Defaults(t *testing.T) {
	content := `
vuls_server:
  url: "https://example.com"
listen_address: "127.0.0.1:9090"
scan_interval: 1h
`
	path := writeTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.VulsServer.Timeout.Duration != 0 {
		t.Errorf("expected zero timeout when not set, got %s", cfg.VulsServer.Timeout.Duration)
	}
	if cfg.VulsServer.CertFile != "" {
		t.Errorf("expected empty cert_file, got %s", cfg.VulsServer.CertFile)
	}
}

func TestLoad_InvalidScanInterval(t *testing.T) {
	content := `
vuls_server:
  url: "https://example.com"
listen_address: "127.0.0.1:9090"
scan_interval: "bogus"
`
	path := writeTempConfig(t, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid scan_interval")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	path := writeTempConfig(t, "")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VulsServer.URL != "" {
		t.Errorf("expected empty URL, got %s", cfg.VulsServer.URL)
	}
	if cfg.ListenAddress != "" {
		t.Errorf("expected empty listen_address, got %s", cfg.ListenAddress)
	}
}

func TestUnmarshalYAML_ValidDurations(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"12h", 12 * time.Hour},
		{"1h30m", time.Hour + 30*time.Minute},
		{"500ms", 500 * time.Millisecond},
		{"0s", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var d Duration
			node := &yaml.Node{Kind: yaml.ScalarNode, Value: tt.input}
			if err := d.UnmarshalYAML(node); err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if d.Duration != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, d.Duration)
			}
		})
	}
}

func TestUnmarshalYAML_InvalidDurations(t *testing.T) {
	tests := []string{
		"not-a-duration",
		"12x",
		"abc",
		"",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			var d Duration
			node := &yaml.Node{Kind: yaml.ScalarNode, Value: input}
			if err := d.UnmarshalYAML(node); err == nil {
				t.Errorf("expected error for %q, got nil", input)
			}
		})
	}
}

func TestUnmarshalYAML_NonStringNode(t *testing.T) {
	var d Duration
	node := &yaml.Node{Kind: yaml.MappingNode}
	if err := d.UnmarshalYAML(node); err == nil {
		t.Fatal("expected error for non-string YAML node")
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
