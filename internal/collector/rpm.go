package collector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type rpmCollector struct {
	family  string
	release string
	// dbPath is the rpm database on the scanned system, empty when that is the
	// system the exporter runs on.
	dbPath string
}

func (r *rpmCollector) CollectPackages(ctx context.Context) (string, string, error) {
	cmd := exec.CommandContext(ctx, "rpm", rpmDBArgs(r.dbPath, "-qa", "--queryformat",
		"%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n")...)
	out, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	pkgs, srcPkgs, err := parseRpmOutput(string(out))
	if err != nil {
		return "", "", err
	}
	return pkgs, srcPkgs, nil
}

func (r *rpmCollector) AvailableUpdates(ctx context.Context) (map[string]string, error) {
	// dnf and yum read the host's repository metadata, which a mounted database
	// does not come with.
	if r.dbPath != "" {
		return nil, nil
	}

	out, err := exec.CommandContext(ctx, "dnf", "check-update").Output()
	if err != nil {
		// dnf exit code 100 means updates are available (not an error).
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 100 {
			return parseDnfCheckUpdate(string(out)), nil
		}
		// dnf not found — try yum.
		if errors.Is(err, exec.ErrNotFound) {
			return rpmAvailableUpdatesYum(ctx)
		}
		return nil, fmt.Errorf("running dnf check-update: %w", err)
	}
	// Exit code 0 means no updates available.
	return nil, nil
}

func rpmAvailableUpdatesYum(ctx context.Context) (map[string]string, error) {
	out, err := exec.CommandContext(ctx, "yum", "check-update").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 100 {
			return parseDnfCheckUpdate(string(out)), nil
		}
		if errors.Is(err, exec.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("running yum check-update: %w", err)
	}
	return nil, nil
}

// parseDnfCheckUpdate parses the output of `dnf check-update` or `yum check-update`.
// Output format (after a blank-line separator from header):
//
//	package.arch    version    repo
func parseDnfCheckUpdate(raw string) map[string]string {
	const minDnfFields = 2 // package.arch, version (repo is optional)

	updates := make(map[string]string)
	pastHeader := false
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			pastHeader = true
			continue
		}
		if !pastHeader {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < minDnfFields {
			continue
		}
		// package.arch → strip the .arch suffix; skip lines without a dot
		// (e.g. "Last metadata expiration check..." header text).
		nameArch := fields[0]
		dotIdx := strings.LastIndex(nameArch, ".")
		if dotIdx <= 0 {
			continue
		}
		name := nameArch[:dotIdx]
		updates[name] = fields[1]
	}
	return updates
}

func (r *rpmCollector) OSFamily() string { return r.family }
func (r *rpmCollector) Release() string  { return r.release }

// parseRpmOutput parses the 6-field rpm -qa output and produces tab-separated
// strings matching the ParsePackages and ParseSrcPackages contracts.
func parseRpmOutput(raw string) (pkgs, srcPkgs string, err error) {
	lines := strings.Split(raw, "\n")
	pkgLines := make([]string, 0, len(lines))
	srcLines := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		const rpmFieldCount = 6 // NAME EPOCHNUM VERSION RELEASE ARCH SOURCERPM
		if len(fields) != rpmFieldCount {
			return "", "", fmt.Errorf("unexpected rpm output line (got %d fields, want %d): %q", len(fields), rpmFieldCount, line)
		}
		name := fields[0]
		epoch := fields[1]
		version := fields[2]
		release := fields[3]
		// fields[4] is ARCH (unused for pkgs line)
		sourceRPM := fields[5]

		// pkgs: name\tii\tepoch:version-release
		pkgLines = append(pkgLines, fmt.Sprintf("%s\tii\t%s:%s-%s", name, epoch, version, release))

		// srcPkgs: srcName\tsrcVersion\tbinaryName\tii
		if srcName, srcVer, ok := parseSourceRPM(sourceRPM); ok {
			srcLines = append(srcLines, fmt.Sprintf("%s\t%s\t%s\tii", srcName, srcVer, name))
		}
	}

	pkgs = strings.Join(pkgLines, "\n")
	if len(pkgLines) > 0 {
		pkgs += "\n"
	}
	srcPkgs = strings.Join(srcLines, "\n")
	if len(srcLines) > 0 {
		srcPkgs += "\n"
	}
	return pkgs, srcPkgs, nil
}

// parseSourceRPM extracts the source package name and version from a SOURCERPM
// field value like "bash-5.1.8-9.el9.src.rpm". It returns false for "(none)"
// or empty values (e.g. GPG keys have no source RPM).
func parseSourceRPM(s string) (name, version string, ok bool) {
	if s == "" || s == "(none)" {
		return "", "", false
	}

	// Strip .src.rpm suffix
	s = strings.TrimSuffix(s, ".src.rpm")

	// NVR format: name-version-release (name can contain hyphens)
	// Find the last two hyphens to split.
	releaseIdx := strings.LastIndex(s, "-")
	if releaseIdx <= 0 {
		return "", "", false
	}
	nameVersion := s[:releaseIdx]
	release := s[releaseIdx+1:]

	versionIdx := strings.LastIndex(nameVersion, "-")
	if versionIdx <= 0 {
		return "", "", false
	}
	name = nameVersion[:versionIdx]
	ver := nameVersion[versionIdx+1:]

	return name, ver + "-" + release, true
}
