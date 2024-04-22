package metrics

import (
	"context"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/prometheus/client_golang/prometheus"
)

var certname string

var generalCVEDetails = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "generalCVEDetails",
		Help: "shows cve score found in availabe security update of linux node",
	},
	[]string{"certname", "application", "cve_id", "score"},
)

var kernelCVEDetails = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kernelCVEDetails",
		Help: "shows cve score found in availabe security update of linux node",
	},
	[]string{"certname", "application", "cve_id", "score"},
)

func RegisterMetrics() {
	prometheus.MustRegister(generalCVEDetails, kernelCVEDetails)
}

func FilterAppsWithNoCVEScore(apps []model.AppCVE) []model.AppCVE {
	logger.GetLogger().Info(context.Background(), "working on filtering out apps with no cve scores", nil)
	filteredApps := make([]model.AppCVE, 0, len(apps))
	for _, app := range apps {
		if len(app.CVEScore) != 0 {
			filteredApps = append(filteredApps, app)
			continue
		}
		logger.GetLogger().Info(context.Background(), "removed an app", map[string]any{"app-name": app.Name})
	}

	return filteredApps
}

func SetCVELabelsValue(appCVEs []model.AppCVE) {
	for _, appCVE := range appCVEs {
		for i := range appCVE.CVEID {
			if strings.Contains(appCVE.Name, "kernel") {
				kernelCVEDetails.WithLabelValues(certname, appCVE.Name, appCVE.CVEID[i], appCVE.CVEScore[i])
				continue
			}
			generalCVEDetails.WithLabelValues(certname, appCVE.Name, appCVE.CVEID[i], appCVE.CVEScore[i])
		}
	}
}

func InitCertname() {
	result, err := exec.Command("puppet", "agent", "--configprint", "certname").Output()
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "failed to get certname of node", err, nil)
	}
	if string(result) == "" {
		logger.GetLogger().Fatal(context.Background(), "certname is empty", err, nil)
	}
	certname = string(result)
}
