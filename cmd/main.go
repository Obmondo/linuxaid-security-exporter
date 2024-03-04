package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"gitea.obmondo.com/EnableIT/security-exporter/config"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/cron"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/metrics"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/server"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/distro"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func main() {
	done := make(chan os.Signal)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	metrics.RegisterMetrics()
	cfg := config.NewConfig(*configPath())
	distro := distro.GetCurrentOS()
	crongService, err := cron.Start(cfg, distro)
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "fatal failed to start cron service", err, nil)
	}

	server.Start(done)

	crongService.Stop()
}

func configPath() *string {
	path := flag.String("config", "./config/config.local.yaml", "Path to the config file")
	flag.Parse()

	logger.GetLogger().Info(context.Background(), "loaded config path", map[string]any{"config path": path})
	return path
}
