package metrics

import (
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"github.com/prometheus/client_golang/prometheus"
)

var cveDetails = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cve_details",
		Help: "shows cve score found in availabe security update of linux node",
	},
	[]string{"application", "cve_id", "severity", "score"},
)

func RegisterMetrics() {
	prometheus.MustRegister(cveDetails)
}

func SetCVELabelsValue(appCVEs []model.AppCVE) {
	for _, appCVE := range appCVEs {
		for i := range appCVE.CVEID {
			cveDetails.WithLabelValues(appCVE.Name, appCVE.CVEID[i], appCVE.CVESeverity[i], appCVE.CVEScore[i])
		}
	}
}
