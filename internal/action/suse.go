package action

import (
	"context"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func newSuse() *suse {
	return &suse{}
}

type suse struct {
}

// GetPackageUpdateList implements Action.
func (s *suse) GetPackageUpdateList() (string, bool, error) {
	logger.GetLogger().Info(context.Background(), logMsgCheckForSecurityUpdate, nil)

	cveOutput, err := exec.Command("zypper", "list-patches", "--cve").Output()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get security update", exitErr, map[string]any{"stderr": string(exitErr.Stderr)})
		}
		return "", false, err
	}

	listUpdatesOutput, err := exec.Command("zypper", "list-updates").Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to run zyper list-updates command", exitErr, map[string]any{"stderr": string(exitErr.Stderr)})
		}
		return "", false, err
	}

	return string(cveOutput), strings.Contains(string(listUpdatesOutput), "kernel-default"), nil

}

// GetChangelogs implements Action.
func (s *suse) GetChangelogs(packageName string) (string, error) {
	return "", nil
}

// GetCurrentPackageVersion implements Action.
func (s *suse) GetCurrentPackageVersion(packageName string) (string, error) {
	return "", nil
}
