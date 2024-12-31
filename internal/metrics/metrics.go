package metrics

import (
	"context"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/prometheus/client_golang/prometheus"
)

var totalNumberOfPackagesWithUpdate = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "total_number_of_packages_with_update",
	Help: "shows total number of package updates on system",
})

var generalCVEDetails = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "general_cve_details",
		Help: "shows cve score found in availabe security update of linux node",
	},
	constants.CveDetailsLabels,
)

var kernelCVEDetails = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kernel_cve_details",
		Help: "shows kernel cve score found in availabe security update of linux node",
	},
	constants.CveDetailsLabels,
)

var kernelUpdates = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "kernel_update_available",
		Help: "shows whether a server has kernel updates",
	})

// We are keeping this for backwords compatablity so that things don't break
// this should be removed after all servers are on latest version of security exporter
// Metrics to be removed in future: kernelCVEDetailsOld, generalCVEDetailsOld, numberOfAppsWithSecurityUpdates
var generalCVEDetailsOld = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "generalCVEDetails",
		Help: "shows cve score found in availabe security update of linux node",
	},
	constants.CveDetailsLabels,
)

var kernelCVEDetailsOld = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kernelCVEDetails",
		Help: "shows cve score found in availabe security update of linux node",
	},
	constants.CveDetailsLabels,
)

var numberOfAppsWithSecurityUpdates = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "number_of_apps_with_security_update",
	Help: "shows number of applications which has security update",
})

func RegisterMetrics() {
	prometheus.MustRegister(generalCVEDetails, kernelCVEDetails, totalNumberOfPackagesWithUpdate, kernelUpdates, numberOfAppsWithSecurityUpdates, generalCVEDetailsOld, kernelCVEDetailsOld)
}

func FilterAppsWithNoCVEScore(apps []model.AppCVE) []model.AppCVE {
	logger.GetLogger().Info(context.Background(), "working on filtering out apps with no cve scores", nil)
	filteredApps := make([]model.AppCVE, 0, len(apps))
	for _, app := range apps {
		logger.GetLogger().Info(context.Background(), "filter process", map[string]any{"app-name": app.Name, "cveIDs": app.CVEID, "cveScore": app.CVEScore})
		if len(app.CVEScore) != 0 && len(app.CVEID) != 0 {
			filteredApps = append(filteredApps, app)
			continue
		}
		logger.GetLogger().Info(context.Background(), "removed an app", map[string]any{"app-name": app.Name})
	}

	return filteredApps
}

func SetCVELabelsValue(appCVEs []model.AppCVE) {
	logger.GetLogger().Info(context.Background(), "setting cve metrics", nil)
	for _, appCVE := range appCVEs {
		logger.GetLogger().Info(context.Background(), "setting metric", map[string]any{"app-name": appCVE.Name, "cveIDs": appCVE.CVEID, "cveScore": appCVE.CVEScore})
		for i := range appCVE.CVEID {
			if strings.Contains(appCVE.Name, "kernel") {
				kernelCVEDetails.WithLabelValues(appCVE.Name, appCVE.CVEID[i], appCVE.CVEScore[i])
				kernelCVEDetailsOld.WithLabelValues(appCVE.Name, appCVE.CVEID[i], appCVE.CVEScore[i])
				continue
			}
			generalCVEDetails.WithLabelValues(appCVE.Name, appCVE.CVEID[i], appCVE.CVEScore[i])
			generalCVEDetailsOld.WithLabelValues(appCVE.Name, appCVE.CVEID[i], appCVE.CVEScore[i])
		}
	}
}

func SetTotalNumberOfPackagesWithUpdate(count int) {
	totalNumberOfPackagesWithUpdate.Set(float64(count))
	numberOfAppsWithSecurityUpdates.Set(float64(count))
}

func SetKernelUpdateMetricForServer(required bool) {
	logger.GetLogger().Info(context.Background(), "setting kernel updates metric", nil)
	if !required {
		kernelUpdates.Set(0)
		return
	}
	kernelUpdates.Set(1)
}
