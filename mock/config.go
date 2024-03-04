package mock

import (
	"context"
	"time"

	"gitea.obmondo.com/EnableIT/security-exporter/config"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/spf13/viper"
)

type mockConfig struct {
	viper *viper.Viper
}

// GetCVECronExpression implements config.Config.
func (m *mockConfig) GetCVECronExpression() string {
	return m.viper.GetString("cron_expression")
}

func (m *mockConfig) GetCVEAPI() string {
	return m.viper.GetString("cve_api.url")
}

func (m *mockConfig) GetCVEAPIEndpoint() string {
	return m.viper.GetString("cve_api.endpoint")
}

func (c *mockConfig) GetCVEAPITimeout() time.Duration {
	return time.Duration(c.viper.GetInt("cve_api.timeout")) * time.Second
}

func (c *mockConfig) GetCVERequestInterval() time.Duration {
	cveRequestInterval := c.viper.GetInt("cve_api.request_interval")
	return time.Duration(cveRequestInterval) * time.Second
}

func MockConfig(path string) config.Config {
	viperConfig := viper.New()
	viperConfig.SetConfigFile(path)

	// reads configuration file
	err := viperConfig.ReadInConfig()
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "error reading config file", err, nil)
	}

	// read the environment variables and store the values in store
	viperConfig.AutomaticEnv()
	return &mockConfig{
		viper: viperConfig,
	}
}
