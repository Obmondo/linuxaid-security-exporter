package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type dpkgCollector struct {
	family  string
	release string
	// adminDir is dpkg's database on the scanned system, empty when that is the
	// system the exporter runs on.
	adminDir string
}

func (d *dpkgCollector) CollectPackages(ctx context.Context) (string, string, error) {
	args := d.dbArgs("-W", "-f",
		"${binary:Package}\t${db:Status-Abbrev}\t${Version}\t${source:Package}\t${source:Version}\n")
	cmd := exec.CommandContext(ctx, "dpkg-query", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", "", err
	}

	const expectedFields = 5
	var pkgs, srcPkgs strings.Builder
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < expectedFields {
			continue
		}
		binary, status, version, srcName, srcVersion := fields[0], fields[1], fields[2], fields[3], fields[4]
		// binary\tstatus\tversion for ParsePackages
		pkgs.WriteString(binary)
		pkgs.WriteByte('\t')
		pkgs.WriteString(status)
		pkgs.WriteByte('\t')
		pkgs.WriteString(version)
		pkgs.WriteByte('\n')
		// source\tsource-version\tbinary\tstatus for ParseSrcPackages
		srcPkgs.WriteString(srcName)
		srcPkgs.WriteByte('\t')
		srcPkgs.WriteString(srcVersion)
		srcPkgs.WriteByte('\t')
		srcPkgs.WriteString(binary)
		srcPkgs.WriteByte('\t')
		srcPkgs.WriteString(status)
		srcPkgs.WriteByte('\n')
	}

	return pkgs.String(), srcPkgs.String(), nil
}

func (d *dpkgCollector) AvailableUpdates(ctx context.Context) (map[string]string, error) {
	// apt reads its own lists and sources, which a mounted host does not provide.
	if d.adminDir != "" {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running apt list --upgradable: %w", err)
	}

	const minFields = 2 // suite, version
	updates := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing...") {
			continue
		}
		// Format: "package/suite version arch [upgradable from: old-version]"
		slashIdx := strings.Index(line, "/")
		if slashIdx < 0 {
			continue
		}
		name := line[:slashIdx]
		rest := line[slashIdx+1:]
		fields := strings.Fields(rest)
		if len(fields) < minFields {
			continue
		}
		updates[name] = fields[1]
	}
	return updates, nil
}

// dbArgs prefixes --admindir when the database being read is a mounted host's.
func (d *dpkgCollector) dbArgs(args ...string) []string {
	if d.adminDir == "" {
		return args
	}
	return append([]string{"--admindir=" + d.adminDir}, args...)
}

func (d *dpkgCollector) OSFamily() string { return d.family }
func (d *dpkgCollector) Release() string  { return d.release }
