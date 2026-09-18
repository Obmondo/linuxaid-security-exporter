package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type zypperCollector struct {
	family  string
	release string
	// dbPath is the rpm database on the scanned system, empty when that is the
	// system the exporter runs on.
	dbPath string
}

func (z *zypperCollector) CollectPackages(ctx context.Context) (string, string, error) {
	cmd := exec.CommandContext(ctx, "rpm", rpmDBArgs(z.dbPath, "-qa", "--queryformat",
		"%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n")...)
	out, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	return parseRpmOutput(string(out))
}

func (z *zypperCollector) AvailableUpdates(ctx context.Context) (map[string]string, error) {
	// zypper reads the host's repositories, which a mounted database does not
	// come with.
	if z.dbPath != "" {
		return nil, nil
	}

	out, err := exec.CommandContext(ctx, "zypper", "--quiet", "list-updates").Output()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("running zypper list-updates: %w", err)
	}
	return parseZypperListUpdates(string(out)), nil
}

func (z *zypperCollector) OSFamily() string { return z.family }
func (z *zypperCollector) Release() string  { return z.release }

// parseZypperListUpdates parses the table output of `zypper --quiet list-updates`.
// Expected format (pipe-separated):
//
//	S | Repository | Name | Current Version | Available Version | Arch
//	--+------------+------+-----------------+-------------------+------
//	v | SLES15-SP5 | bash | 4.4-150400.25.1 | 4.4-150400.27.1   | x86_64
func parseZypperListUpdates(raw string) map[string]string {
	const zypperUpdateFields = 6

	updates := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < zypperUpdateFields {
			continue
		}
		status := strings.TrimSpace(fields[0])
		if status != "v" {
			continue
		}
		name := strings.TrimSpace(fields[2])
		newVersion := strings.TrimSpace(fields[4])
		if name != "" && newVersion != "" {
			updates[name] = newVersion
		}
	}
	return updates
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), exec.ErrNotFound.Error())
}
