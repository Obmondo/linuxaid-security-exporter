package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	"gitea.obmondo.com/EnableIT/security-exporter/config"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/action"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/controller"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/cron"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/cve"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/extracter"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/metrics"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/server"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/distro"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	metrics.RegisterMetrics()

	router := gin.Default()

	actionService, extractorService, cveService, controllerService, cfg := getServices()
	crongService, err := cron.Start(ctx, cfg, actionService, extractorService, cveService)
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "fatal failed to start cron service", err, nil)
	}

	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	router.GET("/total_number_of_packages_with_update", controllerService.GetNumberOfPackageUpdates)
	server.Start(ctx, router, cfg.GetServerHost(), cfg.GetServerPort())
	crongService.Stop()
	crongService.Stop()
}

func getServices() (action.Action, extracter.Extracter, cve.CVEService, controller.Controller, config.Config) {
	cfg := config.NewConfig(*configPath())
	distro := distro.GetCurrentOS()
	actionService := action.NewAction(distro)
	extractorService := extracter.NewExtractor(distro)
	cveService := cve.NewCVEService(cfg)
	controllerService := controller.NewController(actionService, extractorService)
	return actionService, extractorService, cveService, controllerService, cfg
}

func configPath() *string {
	path := flag.String("config", "/etc/obmondo-security-exporter/config.yaml", "Path to the config file")
	flag.Parse()

	logger.GetLogger().Info(context.Background(), "loaded config path", map[string]any{"config path": path})
	return path
}
