package action

import (
	"context"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func newDebianAction() *aptAction {
	return &aptAction{}
}

type aptAction struct{}

func (a *aptAction) GetPackageUpdateList(ctx context.Context, _ constants.UpdateType) (string, bool, error) {
	logger.GetLogger().Info(ctx, logMsgCheckForUpdates, nil)
	output, err := exec.CommandContext(ctx, "apt-get", "upgrade", "-s").CombinedOutput()
	if err != nil {
		logger.GetLogger().Error(ctx, logMsgFailedToGetSystemUpdates, err, map[string]any{"output": string(output)})
		return "", false, err
	}

	return string(output), strings.Contains(string(output), "linux-image"), nil
}

// GetChangelogs implements AptAction.
func (a *aptAction) GetChangelogs(ctx context.Context, packageName string) (string, error) {

	logger.GetLogger().Info(ctx, logMsgGetChangeLogForPackage, map[string]any{"pkg-name": packageName})
	output, err := exec.CommandContext(ctx, "apt-get", "changelog", packageName).CombinedOutput()
	if err != nil {
		logger.GetLogger().Error(ctx, logMsgFailedToGetChangeLogForPackage, err, map[string]any{"package-name": packageName, "output": string(output)})
		return "", err
	}
	return string(output), nil
}

// GetCurrentPackageVersion implements AptAction.
func (a *aptAction) GetCurrentPackageVersion(ctx context.Context, packageName string) (string, error) {
	logger.GetLogger().Info(ctx, logMsgGetPackageVersion, map[string]any{"pkg-name": packageName})
	output, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Version}", packageName).CombinedOutput()
	if err != nil {
		logger.GetLogger().Error(ctx, logMsgGetPackageVersion, err, map[string]any{"package-name": packageName, "output": string(output)})
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
