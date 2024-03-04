package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"gitea.obmondo.com/EnableIT/security-exporter/config"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

type CVEService interface {
	FillAppsDataWithCVEScore(cveIDs ...model.AppCVE) ([]model.AppCVE, []error)
}

type service struct {
	cfg             config.Config
	sustainableRate *time.Ticker
	client          *http.Client
}

// FillAppsDataWithCVEScore implements CVEService.
func (s *service) FillAppsDataWithCVEScore(appCVEs ...model.AppCVE) ([]model.AppCVE, []error) {
	errs := []error{}
	for i, appCVE := range appCVEs {
		cves, err := s.processAppCVE(appCVE)
		if err != nil {
			errs = append(errs, err)
		}
		appCVEs[i] = cves
	}
	return appCVEs, errs
}

func (s *service) processAppCVE(appCVE model.AppCVE) (model.AppCVE, error) {
	for _, cveID := range appCVE.CVEID {
		nvdApiResponse, err := s.getCVEFromAPI(cveID, appCVE.Name)
		if err != nil {
			return appCVE, err
		}

		appCVE.CVEScore = append(appCVE.CVEScore,
			fmt.Sprintf("%.1f",
				nvdApiResponse.
					Vulnerabilities[0].
					Cve.
					Metrics.
					CvssMetricV31[0].
					ImpactScore))

		appCVE.CVESeverity = append(appCVE.CVESeverity,
			nvdApiResponse.
				Vulnerabilities[0].
				Cve.
				Metrics.
				CvssMetricV31[0].
				CvssData.
				IntegrityImpact)

		<-s.sustainableRate.C
	}

	return appCVE, nil
}

func (s *service) getCVEFromAPI(cveID string, appName string) (*model.NVDJsonRespone, error) {
	url := fmt.Sprintf("%s%s?%s=%s", s.cfg.GetCVEAPI(), s.cfg.GetCVEAPIEndpoint(), constants.ParamCVEID, cveID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.GetLogger().Error(req.Context(), "failed to create request", err, nil)
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		logger.GetLogger().Error(resp.Request.Context(), "failed to get cve data from 3rd party api", err, nil)
		return nil, err
	}

	if resp.StatusCode == http.StatusForbidden {
		logger.GetLogger().Error(resp.Request.Context(), "failed to get cve data due to ratelimit", err, map[string]any{"status code": resp.StatusCode})
		return nil, errors.New("rate limit reached")
	}

	defer func() {
		if resp.Body != nil {
			if err := resp.Body.Close(); err != nil {
				logger.GetLogger().Error(resp.Request.Context(), "failed to close response body", err, nil)
			}
		}
	}()

	var nvdApiResponse model.NVDJsonRespone
	if err := json.NewDecoder(resp.Body).Decode(&nvdApiResponse); err != nil {
		logger.GetLogger().Error(context.Background(), "failed to marshal json response", err, map[string]any{"app-name": appName})
		return nil, err
	}

	return &nvdApiResponse, nil
}

func NewCVEService(cfg config.Config) CVEService {
	return &service{
		client: &http.Client{
			Timeout: time.Duration(cfg.GetCVEAPITimeout()),
		},
		sustainableRate: time.NewTicker(cfg.GetCVERequestInterval()),
		cfg:             cfg,
	}
}
