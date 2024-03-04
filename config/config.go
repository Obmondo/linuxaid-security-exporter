package config

import (
	"context"
	"log"
	"time"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/spf13/viper"
)

type Config interface {
	GetCVEAPI() string
	GetCVEAPIEndpoint() string
	GetCVEAPITimeout() time.Duration
	GetCVERequestInterval() time.Duration
	GetCVECronExpression() string
}

type config struct {
	viper *viper.Viper
}

func NewConfig(configPath string) Config {
	viperConfig := viper.New()
	viperConfig.SetConfigFile(configPath)

	// reads configuration file
	err := viperConfig.ReadInConfig()
	if err != nil {
		log.Fatalf("error reading config file, %s", err)
	}

	err = viperConfig.MergeInConfig()
	if err != nil {
		log.Fatalf("error reading config file, %s", err)
	}

	// read the environment variables and store the values in store
	viperConfig.AutomaticEnv()

	return &config{
		viper: viperConfig,
	}
}

func (c *config) sanityCheck() {
	c.GetCVEAPITimeout()
	c.GetCVEAPI()
	c.GetCVEAPIEndpoint()
	c.GetCVERequestInterval()
	c.GetCVECronExpression()
}

func (c *config) GetCVEAPITimeout() time.Duration {
	if c.viper.GetInt("CVE_API_TIMEOUT") == 0 || c.viper.GetInt("cve_api.timeout") == 0 {
		logger.GetLogger().Fatal(context.Background(), "failed to find timeout parameter for CVE API in config and in environment", nil, nil)
	}

	cveTimeout := c.viper.GetInt("CVE_API_TIMEOUT")
	if cveTimeout == 0 {
		cveTimeout = c.viper.GetInt("cve_api.timeout")
	}

	return time.Duration(cveTimeout) * time.Second
}

func (c *config) GetCVERequestInterval() time.Duration {
	if c.viper.GetInt("CVE_API_REQUEST_INTERVAL") == 0 || c.viper.GetInt("cve_api.request_interval") == 0 {
		logger.GetLogger().Fatal(context.Background(), "failed to find timeout paramter for cve api in config and in environment", nil, nil)
	}

	cveRequestInterval := c.viper.GetInt("CVE_API_REQUEST_INTERVAL")
	if cveRequestInterval == 0 {
		cveRequestInterval = c.viper.GetInt("cve_api.request_interval")
	}

	return time.Second * time.Duration(cveRequestInterval)
}

func (c *config) GetCVEAPI() string {
	if len(c.viper.GetString("CVE_API_URL")) == 0 || len(c.viper.GetString("cve_api.url")) == 0 {
		logger.GetLogger().Fatal(context.Background(), "failed to find cve_api value in env and in config file", nil, nil)
	}

	cveAPI := c.viper.GetString("CVE_API_URL")
	if len(cveAPI) == 0 {
		cveAPI = c.viper.GetString("cve_api.url")
	}

	return cveAPI
}

// GetCVEAPIEndpoint implements Config.
func (c *config) GetCVEAPIEndpoint() string {
	if len(c.viper.GetString("CVE_API_ENDPOINT")) == 0 || len(c.viper.GetString("cve_api.endpoint")) == 0 {
		logger.GetLogger().Fatal(context.Background(), "failed to find cve api endpoint in config and in environment", nil, nil)
	}

	cveAPIEndpoint := c.viper.GetString("CVE_API_ENDPOINT")
	if len(cveAPIEndpoint) == 0 {
		cveAPIEndpoint = c.viper.GetString("cve_api.endpoint")
	}

	return cveAPIEndpoint
}

func (c *config) GetCVECronExpression() string {
	if len(c.viper.GetString("CRON_EXPRESSION")) == 0 || len(c.viper.GetString("cron_expression")) == 0 {
		logger.GetLogger().Fatal(context.Background(), "failed to find cron expression in config and in environment", nil, nil)
	}

	cveCronExpression := c.viper.GetString("CRON_EXPRESSION")
	if len(cveCronExpression) == 0 {
		cveCronExpression = c.viper.GetString("cron_expression")
	}

	return cveCronExpression
}
