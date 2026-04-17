# Security Exporter

[![Test](https://github.com/Obmondo/security-exporter/actions/workflows/test.yaml/badge.svg)](https://github.com/Obmondo/security-exporter/actions/workflows/test.yaml)
[![Lint](https://github.com/Obmondo/security-exporter/actions/workflows/lint.yaml/badge.svg)](https://github.com/Obmondo/security-exporter/actions/workflows/lint.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Obmondo/security-exporter)](https://goreportcard.com/report/github.com/Obmondo/security-exporter)

Prometheus exporter that collects installed packages, sends them to a Vuls server for vulnerability scanning, and exposes CVE metrics.

## Configuration

See `config/config.yaml` for an example configuration file.

```yaml
vuls_server:
  url: "https://vulsserver.example"
  timeout: 30s
  cert_file: "/etc/puppetlabs/puppet/ssl/certs/<certname>.pem"
  key_file: "/etc/puppetlabs/puppet/ssl/private_keys/<certname>.pem"
  ca_file: "/etc/puppetlabs/puppet/ssl/certs/ca.pem"
listen_address: "127.254.254.254:63396"
scan_interval: 12h
```

| Field | Description |
|-------|-------------|
| `vuls_server.url` | URL of the Vuls server |
| `vuls_server.timeout` | HTTP request timeout (Go duration) |
| `vuls_server.cert_file` | Client certificate for mTLS (optional) |
| `vuls_server.key_file` | Client key for mTLS (optional) |
| `vuls_server.ca_file` | CA certificate for mTLS (optional) |
| `listen_address` | Address to serve Prometheus metrics on |
| `scan_interval` | How often to scan and push results (Go duration, e.g. `12h`, `30m`) |

## Usage

```sh
obmondo-security-exporter -config /etc/obmondo/security-exporter/config.yaml
```

### One-shot scan

Run a single scan with `scan` subcommand (useful for testing):

```sh
obmondo-security-exporter scan --server https://vulsserver.example --cert-file tls.crt --key-file tls.key
```

Example output:

```
Host:    dev-ashish22
OS:      ubuntu 22.04
CVEs:    37 (92 affected packages)
Packages with updates: 2 / 575

PACKAGE                  INSTALLED                  AVAILABLE  CVE              SEVERITY    FIX VERSION  FIX STATE
gpgv                     2.2.27-3ubuntu2.5          -          CVE-2025-68972   medium      -            deferred
                                                               CVE-2022-3219    low         -            deferred
libpam-runtime           1.4.0-11ubuntu2.6          -          CVE-2025-8941    medium      -            deferred
binutils-x86-64-linux-gnu 2.38-4ubuntu2.12          -          CVE-2025-1180    medium      -            needed
                                                               CVE-2019-1010204 low         -            needed
                                                               CVE-2022-27943   low         -            needed
                                                               CVE-2025-1152    low         -            needed
                                                               CVE-2017-13716   low         -            deferred
                                                               CVE-2022-48064   negligible  -            needed
tar                      1.34+dfsg-1ubuntu0.1.22.04.2 -        CVE-2025-45582   medium      -            needed
busybox-static           1:1.30.1-7ubuntu3.1        -          CVE-2023-42366   medium      -            needed
                                                               CVE-2025-46394   medium      -            needed
                                                               CVE-2024-58251   medium      -            needed
                                                               CVE-2025-60876   medium      -            needed
```

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | Prometheus metrics |
| `/scan` | POST | Trigger an immediate vulnerability scan and return JSON results |

### POST /scan

Triggers an on-demand vulnerability scan, updates Prometheus metrics, and returns a JSON summary with severity breakdown and a comparison against the previous scan.

```sh
curl -X POST http://127.254.254.254:63396/scan
```

Response:

```json
{
  "success": true,
  "total_cves": 6,
  "critical_cves": 0,
  "high_cves": 0,
  "medium_cves": 4,
  "low_cves": 2,
  "packages_with_updates": 1,
  "kernel_update_available": false,
  "previous_total_cves": 17,
  "cves_fixed": 11
}
```

Concurrent scans (cron + HTTP) are mutex-protected — only one scan runs at a time.

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `total_number_of_packages_with_update` | Gauge | — | Total packages with available updates |
| `general_cve_details` | GaugeVec | application, cve_id, score | CVE details for non-kernel packages |
| `kernel_cve_details` | GaugeVec | application, cve_id, score | CVE details for kernel packages |
| `kernel_update_available` | Gauge | — | Whether a kernel update is available (1/0) |
| `security_exporter_scan_up` | Gauge | — | Whether the last scan succeeded (1) or failed (0) |
| `security_exporter_package_high_severity_cves` | GaugeVec | package | Number of CVEs with CVSS3 > 7.0 per package |
| `security_exporter_last_scan_timestamp` | Gauge | — | Unix timestamp of the last successful scan |
| `security_exporter_scan_errors_total` | Counter | — | Total number of failed scans |
| `security_exporter_scan_duration_seconds` | Gauge | — | Duration of the last scan in seconds |
| `security_exporter_os_support_end_timestamp` | GaugeVec | id, version, phase, date | Unix timestamp of each OS support-phase end date (`phase` = `support`, `eol`, `extended`). The `date` label repeats the same instant as an ISO `YYYY-MM-DD` string for readable dashboards and alert annotations. Phases absent for the detected distro are not emitted. |

### OS support-phase metric

`security_exporter_os_support_end_timestamp` exposes end-of-life data sourced from [endoflife.date](https://endoflife.date). The `phase` label distinguishes the three vendor support stages:

- `support` — end of full support (features + free security updates)
- `eol` — end of standard security support (main signal: vendor stops free security updates)
- `extended` — end of paid extended support (Ubuntu Pro, RHEL ELS, SLES LTSS)

Example alert: fire 30 days before free security updates stop.

```promql
(security_exporter_os_support_end_timestamp{phase="eol"} - time()) / 86400 < 30
```

## Development

### Build

```sh
make build
```

`make build` runs `make gen-eol` first, which refreshes `internal/eol/data.json` from [endoflife.date](https://endoflife.date) and embeds it into the binary via `//go:embed`. To refresh the data without rebuilding:

```sh
make gen-eol
```

If the fetch fails (e.g. offline CI), the generator leaves the existing `data.json` untouched so builds can continue with stale data by invoking `go build ./cmd/` directly.

### Test

```sh
make test
```

### Lint

```sh
make lint
```

### Docker Compose

Start a local Vuls stack (server, CVE DB, OVAL DB) with the exporter:

```sh
make docker-up
```

This starts:
- `vuls-server` — Vuls scan server on port 5515
- `vuls-db` — go-cve-dictionary (NVD fetch + server)
- `vuls-oval-db` — goval-dictionary (Debian 12, Ubuntu 22.04/24.04)
- `security-exporter` — the exporter, metrics on port 63396

The first start takes a while as NVD and OVAL data is fetched.

```sh
make docker-logs    # follow logs
make docker-down    # stop and remove containers
```

## Release

Releases are managed via [GoReleaser](https://goreleaser.com/).

- **Gitea** — tag push triggers `.gitea/workflows/release.yaml`, which builds deb/rpm packages via `.goreleaser-gitea.yaml` and uploads them to the package signing server.
- **GitHub** — tag push triggers `.github/workflows/release.yaml`, which creates a GitHub release with changelog and tarballs via `.goreleaser-github.yaml`.

To create a release:

```sh
git tag v1.0.0
git push origin v1.0.0
```
