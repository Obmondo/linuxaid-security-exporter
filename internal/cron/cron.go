package cron

import (
	"context"
	"time"

	"gitea.obmondo.com/EnableIT/security-exporter/config"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/action"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/cve"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/extracter"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/metrics"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/go-co-op/gocron"
)

type service struct {
	actionService    action.Action
	cveService       cve.CVEService
	extractorService extracter.Extracter
	scheduler        *gocron.Scheduler
}

func Start(cfg config.Config, distro constants.Distro) (*service, error) {
	service := newService(cfg, distro)

	if _, err := service.scheduler.Cron(cfg.GetCVECronExpression()).Do(service.collectCVEMetrics); err != nil {
		return nil, err
	}

	return service, nil
}

func (s *service) Stop() {
	if s.scheduler == nil {
		return
	}

	s.scheduler.Stop()
	logger.GetLogger().Info(context.Background(), "cron stopped successfully", nil)
}

func (s *service) collectCVEMetrics() {
	output, err := s.actionService.CheckSecurityForSecurityUpdate()
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "failed to to get action", err, nil)
	}
	apps := s.extractorService.ExtractAppWithSecurityUpdate(output)
	for i, app := range apps {
		version, err := s.actionService.GetCurrentPackageVersion(app.Name)
		if err != nil {
			logger.GetLogger().Fatal(context.Background(), "failed to get pkg version", err, nil)
		}
		changelog, err := s.actionService.GetChangelogs(app.Name)
		if err != nil {
			logger.GetLogger().Error(context.Background(), "failed to get change log", err, nil)
		}
		apps[i].CurrentVersion = version
		apps[i].CVEID = s.extractorService.ExtractCVENumberForGivenChangelog(changelog, version)
	}

	s.cveService.FillAppsDataWithCVEScore(apps...)
	metrics.SetCVELabelsValue(apps)
}

func newService(cfg config.Config, distro constants.Distro) *service {
	return &service{
		scheduler:        gocron.NewScheduler(time.UTC),
		actionService:    action.NewAction(distro),
		extractorService: extracter.NewExtractor(distro),
		cveService:       cve.NewCVEService(cfg),
	}
}
