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
	grepCmd := exec.Command("grep", "security", "/etc/apt/sources.list", "/etc/apt/sources.list.d/*")
	grepOut, err := grepCmd.Output()
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to get grep output", err, nil)
	}

	if err := a.writeToFile("/tmp/security.list", grepOut); err != nil {
		logger.GetLogger().Error(context.Background(), "failed writing security repo list to file", err, nil)
	}

	upgradeCmd := exec.Command("apt-get", "upgrade", "-oDir::Etc::Sourcelist=/tmp/security.list", "-s")
	upgradeOut, err := upgradeCmd.CombinedOutput()
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to get security update", err, nil)
	}

	return string(upgradeOut), nil
}

// GetChangelogs implements AptAction.
func (*aptAction) GetChangelogs(packageName string) (string, error) {
	changelogCmd := exec.Command("apt-get", "changelog", packageName)
	changelogOut, err := changelogCmd.Output()
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to get change log for a package", err, map[string]any{"package-name": packageName})
		return "", err
	}
	return string(changelogOut), nil
}

// GetCurrentPackageVersion implements AptAction.
func (*aptAction) GetCurrentPackageVersion(packageName string) (string, error) {
	dpkgCmd := exec.Command("dpkg-query", "-W", "-f", "${Version}", packageName)
	dpkgOut, err := dpkgCmd.Output()
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to get package Version", err, map[string]any{"package-name": packageName})
		return "", err
	}
	return strings.TrimSpace(string(dpkgOut)), nil
}

func (*aptAction) writeToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
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
