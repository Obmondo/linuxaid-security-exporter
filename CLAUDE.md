# Security Exporter - Claude Code Context

## Project Overview
Prometheus exporter that collects installed packages from Linux hosts, sends them to a Vuls server for vulnerability scanning, and exposes CVE metrics.

## Structure
- `cmd/main.go` — entrypoint: config loading, scheduler (gocron DurationJob), HTTP server, graceful shutdown
- `cmd/serve.go` — daemon mode: cron scheduler, `/metrics` + `/scan` endpoints, `executeScan()` shared between cron and HTTP
- `cmd/scan.go` — one-shot CLI scan subcommand
- `cmd/scan_handler.go` — POST `/scan` HTTP handler: triggers scan, returns JSON with severity breakdown and `cves_fixed`
- `config/` — YAML config parsing with custom `Duration` type
- `internal/pkgscanner/` — HTTP client to Vuls server, mTLS support, request/response types
- `internal/collector/` — OS detection via `/etc/os-release`, package listing via `dpkg-query` (Debian/Ubuntu) or `rpm` (RHEL/CentOS/Rocky/Alma/Fedora) or `zypper` (SLES/SUSE)
- `internal/prommetrics/` — Prometheus gauges: package updates, kernel updates, CVE details, scan_up, per-package high severity CVEs

## Build & Test
```sh
make build      # static linux/amd64 binary → dist/
make test       # go test ./...
make vet        # go vet ./...
make lint       # golangci-lint run ./...
```

## Docker Compose
```sh
make docker-up    # vuls-server + cve-db + oval-db + exporter
make docker-down  # teardown
```

## Release
- Cut with `cog bump --auto` on an up-to-date `master` (`cog.toml`): tags the merged commit and pushes it to `origin` (gitea) and `github`, which is not a mirror
- Gitea: goreleaser with deb/rpm packages (`.goreleaser-gitea.yaml`) + Harbor image
- GitHub: goreleaser with changelog + tarballs (`.goreleaser-github.yaml`) + GHCR image

## Conventions
- Go 1.24, module name `security-exporter`
- Structured logging via `log/slog` (JSON handler to stderr)
- Config uses Go duration strings (`30s`, `12h`) not cron expressions
- golangci-lint config in `.golangci.yaml` (version 2 format)
- Tests use `httptest` servers for scanner, temp files for config/collector
- No `Co-Authored-By` lines in commits

## Key Dependencies
- `github.com/go-co-op/gocron/v2` — scheduler
- `github.com/prometheus/client_golang` — Prometheus metrics
- `gopkg.in/yaml.v3` — config parsing


## Git commit style

- **Mandatory User Approval**: NEVER commit changes unless the user explicitly asks you to.
- **Signed Commits**: Always sign commits when requested (ensure GPG signing is enabled or use `-S`).
- **Pre-commit checks**: Before every commit, run `gofmt -w .` and `golangci-lint run ./...`. Both must be clean — no formatting diffs, no lint issues.
- Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

[optional body]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New user-facing feature |
| `fix` | Bug fix |
| `docs` | Documentation only (README, configuration.md, code comments) |
| `chore` | Maintenance that is not a feature or fix (deps, config, rename, gitignore) |
| `ci` | CI/CD workflow changes (.github/workflows/) |
| `refactor` | Code restructuring with no behaviour change |
| `test` | Adding or fixing tests only |
| `perf` | Performance improvement |
| `build` | Build system changes (Makefile, Dockerfile, .goreleaser.yaml) |
| `style` | Formatting / whitespace only, no logic change |

### Breaking changes

Append `!` after the type/scope for breaking changes:

```
chore!: rename module path to github.com/obmondo/gfetch
feat(api)!: remove deprecated endpoint
```

### Scope

Use the package or subsystem name — keep it short:

```
fix(config): ...
feat(sync): ...
docs(readme): ...
ci(docker): ...
```

Omit scope when the change is repo-wide.

### Subject line rules

- Imperative mood, lowercase, no trailing period
- ≤ 72 characters
- Say *what* changed and *why*, not *how*

### Commit grouping

Commits should be logically atomic — one concern per commit. When a session touches multiple concerns, stage and commit them separately:

1. Code/logic fixes first (`fix`, `feat`, `refactor`)
2. Documentation second (`docs`)
3. Housekeeping last (`chore`, `ci`, `build`)
