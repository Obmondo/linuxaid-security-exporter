package action

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func newDebianAction() *aptAction {
	return &aptAction{}
}

type aptAction struct{}

// CheckSecurityForSecurityUpdate implements AptAction.
func (a *aptAction) CheckSecurityForSecurityUpdate() (string, error) {
	logger.GetLogger().Info(context.Background(), logMsgCheckForSecurityUpdate, nil)
	cmd := "grep --no-filename security /etc/apt/sources.list /etc/apt/sources.list.d/*"
	grepCmd := exec.Command("sh", "-c", cmd)
	grepOut, err := grepCmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get grep output", exitErr, map[string]any{"stderr": string(exitErr.Stderr)})
		}
		return "", err
	}

	if err = a.writeToFile("/tmp/security.list", grepOut); err != nil {
		logger.GetLogger().Error(context.Background(), "failed writing security repo list to file", err, nil)
		return "", err
	}

	upgradeCmd := exec.Command("apt-get", "upgrade", "-oDir::Etc::Sourcelist=/tmp/security.list", "-s")
	upgradeOut, err := upgradeCmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get security update", exitErr, map[string]any{"stderr": string(exitErr.Stderr)})
		}
		return "", err
	}

	return string(upgradeOut), nil
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

func (*aptAction) writeToFile(filename string, data []byte) error {
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}
