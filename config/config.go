package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	VulsServer         VulsServer `yaml:"vuls_server"`
	ListenAddress      string     `yaml:"listen_address"`
	ScanInterval       Duration   `yaml:"scan_interval"`
	RandomDelay        Duration   `yaml:"random_delay"`
	UpstreamRetryDelay Duration   `yaml:"upstream_retry_delay"`
}

type VulsServer struct {
	URL      string   `yaml:"url"`
	Timeout  Duration `yaml:"timeout"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
	CAFile   string   `yaml:"ca_file"`
}

// Duration wraps time.Duration for YAML unmarshaling.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	slog.Info("loaded config",
		"path", path,
		"scan_interval", cfg.ScanInterval.Duration,
		"random_delay", cfg.GetRandomDelay(),
		"upstream_retry_delay", cfg.UpstreamRetryDelay.Duration,
	)
	return &cfg, nil
}

func (c *Config) GetRandomDelay() time.Duration {
	if c.RandomDelay.Duration == 0 {
		return time.Hour
	}
	return c.RandomDelay.Duration
}
