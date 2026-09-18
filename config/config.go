package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// nodeNameEnv carries the node name into a pod from the downward API, since a
// ConfigMap cannot hold a per-node value.
const nodeNameEnv = "NODE_NAME"

type Config struct {
	VulsServer         VulsServer `yaml:"vuls_server"`
	ListenAddress      string     `yaml:"listen_address"`
	ScanInterval       Duration   `yaml:"scan_interval"`
	RandomDelay        Duration   `yaml:"random_delay"`
	UpstreamRetryDelay Duration   `yaml:"upstream_retry_delay"`
	// HostRoot is the scanned system's filesystem root: empty on a host, or the
	// node root mounted into a container (e.g. /host).
	HostRoot string `yaml:"host_root"`
	// NodeName separates hosts that share one certificate, such as the nodes of
	// a Kubernetes cluster. Falls back to $NODE_NAME, which a pod gets from the
	// downward API.
	NodeName string `yaml:"node_name"`
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
	if cfg.NodeName == "" {
		cfg.NodeName = os.Getenv(nodeNameEnv)
	}
	slog.Info("loaded config",
		"path", path,
		"scan_interval", cfg.ScanInterval.Duration,
		"random_delay", cfg.GetRandomDelay(),
		"upstream_retry_delay", cfg.UpstreamRetryDelay.Duration,
		"host_root", cfg.HostRoot,
		"node_name", cfg.NodeName,
	)
	return &cfg, nil
}

func (c *Config) GetRandomDelay() time.Duration {
	if c.RandomDelay.Duration == 0 {
		return time.Hour
	}
	return c.RandomDelay.Duration
}
