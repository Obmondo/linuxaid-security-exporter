package prommetrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"security-exporter/internal/pkgscanner"
)

func TestUpdate(t *testing.T) {
	result := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"openssl":         {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
			"bash":            {Name: "bash", Version: "5.2.21-1", NewVersion: ""},
			"linux-image-6.1": {Name: "linux-image-6.1", Version: "6.1.90-1", NewVersion: "6.1.99-1"},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{CveID: "CVE-2024-1234", Cvss3Score: 7.5}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
			"CVE-2024-5678": {
				CveID: "CVE-2024-5678",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{CveID: "CVE-2024-5678", Cvss3Score: 5.0}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
					{Name: "linux-image-6.1"},
				},
			},
		},
	}

	Update(result)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 2 {
		t.Errorf("expected 2 packages with updates, got %f", v)
	}
	if v := testutil.ToFloat64(kernelUpdateAvailable); v != 1 {
		t.Errorf("expected kernel update available = 1, got %f", v)
	}
}

func TestUpdate_GeneralCVEGauge(t *testing.T) {
	result := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"openssl": {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{CveID: "CVE-2024-1234", Cvss3Score: 7.5}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
		},
	}

	Update(result)

	v := testutil.ToFloat64(generalCVEDetails.WithLabelValues("openssl", "CVE-2024-1234", "7.5"))
	if v != 7.5 {
		t.Errorf("expected general CVE gauge 7.5, got %f", v)
	}
}

func TestUpdate_KernelCVEGauge(t *testing.T) {
	result := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"linux-image-6.1": {Name: "linux-image-6.1", Version: "6.1.90-1", NewVersion: "6.1.99-1"},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{
			"CVE-2024-5678": {
				CveID: "CVE-2024-5678",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{CveID: "CVE-2024-5678", Cvss3Score: 5.0}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
					{Name: "linux-image-6.1"},
				},
			},
		},
	}

	Update(result)

	v := testutil.ToFloat64(kernelCVEDetails.WithLabelValues("linux-image-6.1", "CVE-2024-5678", "5.0"))
	if v != 5.0 {
		t.Errorf("expected kernel CVE gauge 5.0, got %f", v)
	}
}

func TestSetLastScanTimestamp(t *testing.T) {
	SetLastScanTimestamp()
	v := testutil.ToFloat64(lastScanTimestamp)
	if v == 0 {
		t.Error("expected non-zero timestamp after SetLastScanTimestamp")
	}
}

func TestIncrScanErrors(t *testing.T) {
	before := testutil.ToFloat64(scanErrorsTotal)
	IncrScanErrors()
	after := testutil.ToFloat64(scanErrorsTotal)
	if after != before+1 {
		t.Errorf("expected scan errors to increment by 1, got before=%f after=%f", before, after)
	}
}

func TestSetScanDuration(t *testing.T) {
	SetScanDuration(3.14)
	v := testutil.ToFloat64(scanDurationSeconds)
	if v != 3.14 {
		t.Errorf("expected scan duration 3.14, got %f", v)
	}
}

func TestSetOSSupportDates(t *testing.T) {
	osSupportEndTimestamp.Reset()
	t.Cleanup(func() { osSupportEndTimestamp.Reset() })

	SetOSSupportDates("ubuntu", "24.04")

	// The date label must mirror the underlying timestamp in ISO form, so
	// gather samples and check both value and label together.
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := map[string]struct {
		ts   float64
		date string
	}{}
	for _, mf := range mfs {
		if mf.GetName() != "security_exporter_os_support_end_timestamp" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var phase, date string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "phase":
					phase = l.GetValue()
				case "date":
					date = l.GetValue()
				}
			}
			got[phase] = struct {
				ts   float64
				date string
			}{m.GetGauge().GetValue(), date}
		}
	}
	for _, phase := range []string{"support", "eol", "extended"} {
		s, ok := got[phase]
		if !ok {
			t.Errorf("phase %q: missing sample", phase)
			continue
		}
		if s.ts <= 0 {
			t.Errorf("phase %q: expected non-zero timestamp, got %f", phase, s.ts)
		}
		want := time.Unix(int64(s.ts), 0).UTC().Format("2006-01-02")
		if s.date != want {
			t.Errorf("phase %q: date label %q, want %q (from ts %f)", phase, s.date, want, s.ts)
		}
	}
}

func TestSetOSSupportDates_UnknownDistro(t *testing.T) {
	osSupportEndTimestamp.Reset()
	t.Cleanup(func() { osSupportEndTimestamp.Reset() })

	SetOSSupportDates("arch", "rolling")

	if n := testutil.CollectAndCount(osSupportEndTimestamp); n != 0 {
		t.Errorf("expected no samples for unknown distro, got %d", n)
	}
}

func TestUpdate_ResetsBetweenCalls(t *testing.T) {
	first := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"openssl": {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{CveID: "CVE-2024-1234", Cvss3Score: 7.5}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
		},
	}
	Update(first)

	second := &pkgscanner.ScanResult{
		Packages:    pkgscanner.Packages{},
		ScannedCves: map[string]pkgscanner.VulnInfo{},
	}
	Update(second)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 0 {
		t.Errorf("expected 0 after second update, got %f", v)
	}
}
