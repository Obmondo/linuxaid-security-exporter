package collector

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Package databases on the scanned system, relative to its root.
const (
	dpkgAdminDir = "/var/lib/dpkg"
	rpmDBDir     = "/var/lib/rpm"
)

type Collector interface {
	CollectPackages(ctx context.Context) (pkgs, srcPkgs string, err error)
	AvailableUpdates(ctx context.Context) (map[string]string, error)
	OSFamily() string
	Release() string
}

// New builds the collector for the system under hostRoot: empty for the system
// the exporter runs on, or a mounted host root, whose package database the
// tools are pointed at instead of their own.
func New(hostRoot string) (Collector, error) {
	id, versionID, err := DetectOS(hostRoot)
	if err != nil {
		return nil, fmt.Errorf("detecting OS: %w", err)
	}

	slog.Info("detected OS", "id", id, "version", versionID, "host_root", hostRoot)

	switch id {
	case "debian", "ubuntu":
		return &dpkgCollector{family: id, release: versionID, adminDir: databasePath(hostRoot, dpkgAdminDir)}, nil
	case "rhel", "centos", "rocky", "ol", "almalinux", "fedora":
		return &rpmCollector{family: "redhat", release: versionID, dbPath: databasePath(hostRoot, rpmDBDir)}, nil
	case "sles", "suse":
		return &zypperCollector{
			family:  "suse.linux.enterprise.server",
			release: versionID,
			dbPath:  databasePath(hostRoot, rpmDBDir),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported OS family: %s", id)
	}
}

// databasePath locates a package database under a mounted host root. It stays
// empty for a local scan, where each tool finds its own database.
func databasePath(hostRoot, path string) string {
	if hostRoot == "" {
		return ""
	}
	return filepath.Join(hostRoot, path)
}

// rpmDBArgs prefixes --dbpath when the database being read is a mounted host's.
func rpmDBArgs(dbPath string, args ...string) []string {
	if dbPath == "" {
		return args
	}
	return append([]string{"--dbpath=" + dbPath}, args...)
}

// DetectOS reads os-release under hostRoot and returns the lowercased ID and raw
// VERSION_ID. Exported so other packages (e.g. eol metric setup) can use
// the same source of truth without duplicating the parser.
func DetectOS(hostRoot string) (id, versionID string, err error) {
	return parseOSRelease(filepath.Join(hostRoot, "/etc/os-release"))
}

func parseOSRelease(path string) (id, versionID string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		const kvParts = 2
		parts := strings.SplitN(line, "=", kvParts)
		if len(parts) == kvParts {
			fields[parts[0]] = strings.Trim(parts[1], "\"")
		}
	}

	id = strings.ToLower(fields["ID"])
	versionID = fields["VERSION_ID"]
	if id == "" {
		return "", "", fmt.Errorf("ID not found in %s", path)
	}
	return id, versionID, nil
}
