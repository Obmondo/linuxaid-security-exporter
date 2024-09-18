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
	"gitea.obmondo.com/EnableIT/security-exporter/utils/distro"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/go-co-op/gocron/v2"
)

var errFailedToGetCVEScores = errors.New("unable to fetch cve scores of apps")

type service struct {
	actionService    action.Action
	cveService       cve.CVEService
	extractorService extracter.Extracter
	scheduler        gocron.Scheduler
}

func Start(cfg config.Config, distro constants.Distro) (*service, error) {
	service := newService(cfg, distro)
	ctx := context.Background()

	switch {
	case cfg.GetRunType() == constants.RunTypeTest:
		_, err := service.scheduler.NewJob(gocron.OneTimeJob(gocron.OneTimeJobStartImmediately()), gocron.NewTask(service.collectCVEMetrics, ctx))
		if err != nil {
			return nil, err
		}
	default:
		if _, err := service.scheduler.NewJob(gocron.CronJob(cfg.GetCVECronExpression(), false), gocron.NewTask(service.collectCVEMetrics, ctx), gocron.WithSingletonMode(gocron.LimitModeReschedule)); err != nil {
			return nil, err
		}
	}

	service.scheduler.Start()
	return service, nil
}

func (s *service) Stop() {
	if s.scheduler == nil {
		return
	}

	if err := s.scheduler.Shutdown(); err != nil {
		logger.GetLogger().Error(context.Background(), "cron failed to shutdown", err, nil)
	}
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
	apps = metrics.FilterAppsWithNoCVEScore(apps)
	metrics.SetCVELabelsValue(apps)
}

func (s *service) getAllParamsRelatedToAppWithSecurityUpdate(ctx context.Context, output string) []model.AppCVE {
	apps := s.extractorService.ExtractAppWithSecurityUpdate(output)

	metrics.SetNumberOfAppsWithSecurityUpdate(len(apps))
	if distro.GetCurrentOS() == constants.SUSE {
		return apps
	}

	for i, app := range apps {
		logger.GetLogger().Info(ctx, "starting to process app", map[string]any{"index": i, "app-name": app.Name})
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
	scheduler, err := gocron.NewScheduler(gocron.WithLocation(time.UTC))
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "failed to start scheduler", err, nil)
	}
	return &service{
		scheduler:        scheduler,
		actionService:    action.NewAction(distro),
		extractorService: extracter.NewExtractor(distro),
		cveService:       cve.NewCVEService(cfg),
	}
}
