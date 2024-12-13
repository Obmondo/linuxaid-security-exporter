package cron

import (
	"context"

	"gitea.obmondo.com/EnableIT/security-exporter/config"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/action"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/cve"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/extracter"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/go-co-op/gocron/v2"
)

func Start(ctx context.Context, cfg config.Config, action action.Action, extracter extracter.Extracter, cveService cve.CVEService) (*service, error) {
	svc := newService(action, extracter, cveService)

	if err := svc.createJob(cfg, ctx); err != nil {
		return nil, err
	}

	svc.scheduler.Start()
	return svc, nil
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

func (s *service) createJob(cfg config.Config, ctx context.Context) error {
	switch cfg.GetRunType() {
	case constants.RunTypeTest:
		_, err := s.scheduler.NewJob(
			gocron.OneTimeJob(gocron.OneTimeJobStartImmediately()),
			gocron.NewTask(s.collectCVEAndKernelUpdateMetrics, ctx),
		)
		return err
	default:
		_, err := s.scheduler.NewJob(
			gocron.CronJob(cfg.GetCVECronExpression(), false),
			gocron.NewTask(s.collectCVEAndKernelUpdateMetrics, ctx),
			gocron.WithSingletonMode(gocron.LimitModeReschedule),
		)
		return err
	}
}
