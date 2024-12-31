package cron

import (
	"context"
	"errors"
	"time"

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

func (s *service) collectCVEAndKernelUpdateMetrics(ctx context.Context) {
	if distro.GetCurrentOS() == constants.SUSE {
		s.collectSUSEMetrics(ctx)
	} else {
		s.collectDefaultMetrics(ctx)
	}
}

func (s *service) collectSUSEMetrics(ctx context.Context) {
	output, isKernelUpdate, err := s.actionService.GetPackageUpdateList(ctx, constants.UpdateTypeALL)
	if err != nil {
		return
	}
	metrics.SetTotalNumberOfPackagesWithUpdate(s.extractorService.NumberOfAppsInSystemUpdate(output))
	metrics.SetKernelUpdateMetricForServer(isKernelUpdate)
	output, _, err = s.actionService.GetPackageUpdateList(ctx, constants.UpdateTypeSecurity)
	if err != nil {
		return
	}
	apps := s.extractorService.ExtractAppWithSecurityUpdate(output)

	s.getCVEScoresForApps(ctx, apps)
}

func (s *service) collectDefaultMetrics(ctx context.Context) {
	output, isKernelUpdate, err := s.actionService.GetPackageUpdateList(ctx, constants.UpdateTypeSecurity)
	if err != nil {
		logger.GetLogger().Error(ctx, "failed to get updates", err, nil)
		return
	}

	metrics.SetKernelUpdateMetricForServer(isKernelUpdate)
	apps := s.getAppsWithCVEIDs(ctx, output)
	if len(apps) == 0 {
		logger.GetLogger().Info(ctx, "no apps with security update found", nil)
		return
	}

	s.getCVEScoresForApps(ctx, apps)
}

func (s *service) getAppsWithCVEIDs(ctx context.Context, output string) []model.AppCVE {
	apps := s.extractorService.ExtractAppWithSecurityUpdate(output)
	metrics.SetTotalNumberOfPackagesWithUpdate(len(apps))
	for i, app := range apps {
		logger.GetLogger().Info(ctx, "starting to process app", map[string]any{"index": i, "app-name": app.Name})
		version, err := s.actionService.GetCurrentPackageVersion(ctx, app.Name)
		if err != nil {
			logger.GetLogger().Error(ctx, "failed to to get current pkg version", err, nil)
			continue
		}
		changelog, err := s.actionService.GetChangelogs(ctx, app.Name)
		if err != nil {
			logger.GetLogger().Error(ctx, "failed to get change log", err, nil)
			continue
		}
		apps[i].CVEID = s.extractorService.ExtractCVENumberForGivenChangelog(changelog, version)
	}

	return apps
}

func (s *service) getCVEScoresForApps(ctx context.Context, apps []model.AppCVE) {
	apps, failedToFetchForAllApps, errs := s.cveService.FillAppsDataWithCVEScore(ctx, apps...)
	if failedToFetchForAllApps {
		logger.GetLogger().Error(ctx, "errors occured while fetching cve score of all apps", errFailedToGetCVEScores, map[string]any{"errors": errs})
		return
	}
	if len(errs) != 0 {
		logger.GetLogger().Info(ctx, "errors occured while fetching cve scores of apps, not all apps maybe present in metrics", map[string]any{"errors": errs})
	}
	apps = metrics.FilterAppsWithNoCVEScore(apps)
	metrics.SetCVELabelsValue(apps)
}

func newService(action action.Action, extracter extracter.Extracter, cveService cve.CVEService) *service {
	scheduler, err := gocron.NewScheduler(gocron.WithLocation(time.UTC))
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "failed to start scheduler", err, nil)
	}
	return &service{
		scheduler:        scheduler,
		actionService:    action,
		extractorService: extracter,
		cveService:       cveService,
	}
}
