package cron

import (
	"context"
	"errors"
	"time"

	"gitea.obmondo.com/EnableIT/security-exporter/config"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/action"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/cve"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/extracter"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/metrics"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/go-co-op/gocron"
)

var errFailedToGetCVEScores = errors.New("unable to fetch cve scores of apps")

type service struct {
	actionService    action.Action
	cveService       cve.CVEService
	extractorService extracter.Extracter
	scheduler        *gocron.Scheduler
}

func Start(cfg config.Config, distro constants.Distro) (*service, error) {
	service := newService(cfg, distro)

	ctx := context.Background()
	if _, err := service.scheduler.Cron(cfg.GetCVECronExpression()).Do(service.collectCVEMetrics, ctx); err != nil {
		return nil, err
	}

	service.scheduler.StartAsync()
	return service, nil
}

func (s *service) Stop() {
	if s.scheduler == nil {
		return
	}

	s.scheduler.Stop()
	logger.GetLogger().Info(context.Background(), "cron stopped successfully", nil)
}

func (s *service) collectCVEMetrics(ctx context.Context) {

	output, err := s.actionService.CheckSecurityForSecurityUpdate()
	if err != nil {
		logger.GetLogger().Error(ctx, "failed to find security update", err, nil)
		return
	}

	// fills  appCVE slice with current versison and CVEIds
	apps := s.getAllParamsRelatedToAppWithSecurityUpdate(ctx, output)
	if len(apps) == 0 {
		logger.GetLogger().Info(ctx, "no apps with security update found", nil)
		return
	}

	apps, errs := s.cveService.FillAppsDataWithCVEScore(apps...)
	if len(errs) == len(apps) {
		logger.GetLogger().Error(ctx, "errors occured while fetching cve score of all apps", errFailedToGetCVEScores, map[string]any{"errors": errs})
		return
	}
	if len(errs) != 0 {
		logger.GetLogger().Info(ctx, "errors occured while fetching cve scores of apps, not all apps maybe present in metrics", map[string]any{"errors": errs})
	}

	metrics.SetCVELabelsValue(metrics.FilterAppsWithNoCVEScore(apps))
}

func (s *service) getAllParamsRelatedToAppWithSecurityUpdate(ctx context.Context, output string) []model.AppCVE {
	apps := s.extractorService.ExtractAppWithSecurityUpdate(output)
	for i, app := range apps {
		version, err := s.actionService.GetCurrentPackageVersion(app.Name)
		if err != nil {
			logger.GetLogger().Error(ctx, "failed to to get current pkg version", err, nil)
			continue
		}
		changelog, err := s.actionService.GetChangelogs(app.Name)
		if err != nil {
			logger.GetLogger().Error(ctx, "failed to get change log", err, nil)
			continue
		}
		apps[i].CVEID = s.extractorService.ExtractCVENumberForGivenChangelog(changelog, version)
	}

	return apps
}

func newService(cfg config.Config, distro constants.Distro) *service {
	return &service{
		scheduler:        gocron.NewScheduler(time.UTC),
		actionService:    action.NewAction(distro),
		extractorService: extracter.NewExtractor(distro),
		cveService:       cve.NewCVEService(cfg),
	}
}
