package action

import (
	"context"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func newDebianAction() *aptAction {
	return &aptAction{}
}

type aptAction struct{}

// GetPackageUpdateList implements AptAction.
func (a *aptAction) GetPackageUpdateList() (string, bool, error) {
	logger.GetLogger().Info(context.Background(), logMsgCheckForSecurityUpdate, nil)

	upgradeCmd := exec.Command("apt-get", "upgrade", "-s")
	upgradeOut, err := upgradeCmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get package updates list", exitErr, map[string]any{"stderr": string(exitErr.Stderr)})
		}
		return "", false, err
	}

	return string(upgradeOut), strings.Contains(string(upgradeOut), "linux-image"), nil
}

// GetChangelogs implements AptAction.
func (*aptAction) GetChangelogs(packageName string) (string, error) {
	logger.GetLogger().Info(context.Background(), logMsgGetChangeLogForPackage, map[string]any{"pkg-name": packageName})
	changelogCmd := exec.Command("apt-get", "changelog", packageName)
	changelogOut, err := changelogCmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get change log for a package", exitErr, map[string]any{"package-name": packageName, "stderr": exitErr.Stderr})
		}
		return "", err
	}
	return string(changelogOut), nil
}

// GetCurrentPackageVersion implements AptAction.
func (*aptAction) GetCurrentPackageVersion(packageName string) (string, error) {
	logger.GetLogger().Info(context.Background(), logMsgGetPackageVersion, map[string]any{"pkg-name": packageName})
	dpkgCmd := exec.Command("dpkg-query", "-W", "-f", "${Version}", packageName)
	dpkgOut, err := dpkgCmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get package Version", exitErr, map[string]any{"package-name": packageName, "stderr": exitErr.Stderr})
		}
		return "", err
	}
	return strings.TrimSpace(string(dpkgOut)), nil
}
