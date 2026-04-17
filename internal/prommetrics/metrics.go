package prommetrics

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"security-exporter/internal/eol"
	"security-exporter/internal/pkgscanner"
)

const highSeverityThreshold = 7.0

var (
	totalPackagesWithUpdate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "total_number_of_packages_with_update",
		Help: "Total number of packages that have updates available.",
	})

	generalCVEDetails = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "general_cve_details",
		Help: "CVE details for non-kernel packages.",
	}, []string{"application", "cve_id", "score"})

	kernelCVEDetails = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kernel_cve_details",
		Help: "CVE details for kernel packages.",
	}, []string{"application", "cve_id", "score"})

	kernelUpdateAvailable = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kernel_update_available",
		Help: "Whether a kernel update is available (1 = yes, 0 = no).",
	})

	lastScanTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "security_exporter_last_scan_timestamp",
		Help: "Unix timestamp of the last successful scan.",
	})

	scanErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "security_exporter_scan_errors_total",
		Help: "Total number of failed scans.",
	})

	scanDurationSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "security_exporter_scan_duration_seconds",
		Help: "Duration of the last scan in seconds.",
	})

	scanUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "security_exporter_scan_up",
		Help: "Whether the last vulnerability scan succeeded (1 = success, 0 = failure).",
	})

	packageHighSeverityCVEs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "security_exporter_package_high_severity_cves",
		Help: "Number of CVEs with CVSS3 score greater than 7.0 per package.",
	}, []string{"package"})

	osSupportEndTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "security_exporter_os_support_end_timestamp",
		Help: "Unix timestamp of the end of an OS support phase (support=full support, eol=standard security updates, extended=paid extended support). The date label repeats the same instant in ISO YYYY-MM-DD form for readability. Emitted per phase; missing phases are absent.",
	}, []string{"id", "version", "phase", "date"})
)

// SetLastScanTimestamp records the current time as the last successful scan.
func SetLastScanTimestamp() {
	lastScanTimestamp.Set(float64(time.Now().Unix()))
}

// IncrScanErrors increments the scan error counter.
func IncrScanErrors() {
	scanErrorsTotal.Inc()
}

// SetScanDuration records the duration of the last scan.
func SetScanDuration(d float64) {
	scanDurationSeconds.Set(d)
}

// SetScanUp records whether the last scan succeeded (true) or failed (false).
func SetScanUp(up bool) {
	if up {
		scanUp.Set(1)
	} else {
		scanUp.Set(0)
	}
}

// SetOSSupportDates emits one gauge sample per known support-phase date
// (support, eol, extended) for the given /etc/os-release ID and
// VERSION_ID. Phases with no known date are left absent so PromQL
// absent() queries work. Logs a warning and emits nothing when the
// distro or cycle is not in the embedded EOL data.
func SetOSSupportDates(id, version string) {
	phases, ok := eol.Lookup(id, version)
	if !ok {
		slog.Warn("no EOL data for detected OS", "id", id, "version", version)
		return
	}
	emit := func(phase string, t time.Time) {
		if t.IsZero() {
			return
		}
		osSupportEndTimestamp.WithLabelValues(id, version, phase, t.UTC().Format("2006-01-02")).Set(float64(t.Unix()))
	}
	emit("support", phases.Support)
	emit("eol", phases.EOL)
	emit("extended", phases.Extended)
}

func Update(result *pkgscanner.ScanResult) {
	generalCVEDetails.Reset()
	kernelCVEDetails.Reset()

	updateCount := 0
	kernelUpdate := false

	for _, pkg := range result.Packages {
		if pkg.NewVersion != "" {
			updateCount++
			if isKernelPackage(pkg.Name) {
				kernelUpdate = true
			}
		}
	}
	totalPackagesWithUpdate.Set(float64(updateCount))

	if kernelUpdate {
		kernelUpdateAvailable.Set(1)
	} else {
		kernelUpdateAvailable.Set(0)
	}

	slog.Info("updating metrics", "packages_with_updates", updateCount, "cves", len(result.ScannedCves))

	packageHighSeverityCVEs.Reset()
	highCountByPkg := make(map[string]int)

	for _, vuln := range result.ScannedCves {
		score := BestCVSS3Score(vuln)
		scoreStr := fmt.Sprintf("%.1f", score)

		if score > highSeverityThreshold {
			for _, pkg := range vuln.AffectedPackages {
				highCountByPkg[pkg.Name]++
			}
		}

		for _, pkg := range vuln.AffectedPackages {
			gauge := generalCVEDetails
			if isKernelPackage(pkg.Name) {
				gauge = kernelCVEDetails
			}
			gauge.WithLabelValues(pkg.Name, vuln.CveID, scoreStr).Set(score)
		}
	}

	for pkg, count := range highCountByPkg {
		packageHighSeverityCVEs.WithLabelValues(pkg).Set(float64(count))
	}
}

func isKernelPackage(name string) bool {
	return strings.HasPrefix(name, "linux-image") ||
		strings.HasPrefix(name, "linux-headers") ||
		name == "kernel" ||
		strings.HasPrefix(name, "kernel-")
}

func BestCVSS3Score(v pkgscanner.VulnInfo) float64 {
	var best float64
	for _, contents := range v.CveContents {
		for _, c := range contents {
			if c.Cvss3Score > best {
				best = c.Cvss3Score
			}
		}
	}
	return best
}
