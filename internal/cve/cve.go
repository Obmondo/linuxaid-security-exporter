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
	logger.GetLogger().Info(context.Background(), "fetching cve scores for packages", nil)
	s.sustainableRate = time.NewTicker(s.cfg.GetCVERequestInterval())
	defer s.sustainableRate.Stop()

	errs := make([]error, 0, len(appCVEs))
	for i, appCVE := range appCVEs {
		cves, errList := s.processAppCVE(appCVE)
		if len(errList) != 0 {
			errs = append(errs, errList...)
		}
		appCVEs[i] = cves
	}
	return appCVEs, errs
}

func (s *service) processAppCVE(appCVE model.AppCVE) (model.AppCVE, []error) {
	errs := []error{}
	cveIDWithNoScore := make(map[string]bool)
	for _, cveID := range appCVE.CVEID {
		<-s.sustainableRate.C

		logger.GetLogger().Info(context.Background(), "fetching cve score for app", map[string]any{"app-name": appCVE.Name, "cveID": cveID})
		nvdAPIResponse, err := s.getCVEFromAPI(cveID, appCVE.Name)
		if err != nil {
			errs = append(errs, err)
		}
		if nvdAPIResponse != nil && nvdAPIResponse.Vulnerabilities != nil && len(nvdAPIResponse.Vulnerabilities[0].Cve.Metrics.CvssMetricV31) != 0 {
			appCVE.CVEScore = append(appCVE.CVEScore,
				fmt.Sprintf("%.1f",
					nvdAPIResponse.
						Vulnerabilities[0].
						Cve.
						Metrics.
						CvssMetricV31[0].CvssData.BaseScore))
		} else {
			cveIDWithNoScore[cveID] = true
			logger.GetLogger().Error(context.Background(), "json did not contain CVE Score", errors.New("response json did not had CVE Score"), map[string]any{"app-name": appCVE.Name})
		}

	}

	return s.filterAppCVEID(appCVE, cveIDWithNoScore), errs
}

func (s *service) filterAppCVEID(app model.AppCVE, mp map[string]bool) model.AppCVE {
	filteredCVEWithResponse := make([]string, 0, len(app.CVEID)-len(mp))
	for _, cveID := range app.CVEID {
		if mp[cveID] {
			continue
		}
		filteredCVEWithResponse = append(filteredCVEWithResponse, cveID)
	}

	app.CVEID = filteredCVEWithResponse
	return app
}

func (s *service) getCVEFromAPI(cveID string, appName string) (*model.NVDJsonRespone, error) {
	url := fmt.Sprintf("%s%s?%s=%s", s.cfg.GetCVEAPI(), s.cfg.GetCVEAPIEndpoint(), constants.ParamCVEID, cveID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	logger.GetLogger().Info(context.Background(), "creating request", map[string]any{"app-name": appName, "url": url})
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to create request", err, map[string]any{"app-name": appName})
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to get cve data from 3rd party api", err, map[string]any{"app-name": appName})
		return nil, err
	}

	if resp.StatusCode == http.StatusForbidden {
		logger.GetLogger().Error(context.Background(), "failed to get cve data due to ratelimit", err, map[string]any{"status code": resp.StatusCode, "app-name": appName})
		return nil, errors.New("rate limit reached")
	}

	defer func() {
		if resp.Body != nil {
			if err := resp.Body.Close(); err != nil {
				logger.GetLogger().Error(context.Background(), "failed to close response body", err, map[string]any{"app-name": appName})
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
		cfg: cfg,
	}
}
