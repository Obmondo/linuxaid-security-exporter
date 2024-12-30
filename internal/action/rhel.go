package action

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func newRhelAction() *rhel {
	return &rhel{}
}

type rhel struct {
}

func (r *rhel) GetPackageUpdateList(ctx context.Context, _ constants.UpdateType) (string, bool, error) {
	logger.GetLogger().Info(ctx, logMsgCheckForUpdates, nil)
	output, err := exec.CommandContext(ctx, "yum", "check-update").CombinedOutput()
	if err != nil && !strings.Contains(err.Error(), "exit status 100") {
		logger.GetLogger().Error(ctx, logMsgFailedToGetSystemUpdates, err, map[string]any{"output": string(output)})
		return "", false, err
	}

	return string(output), strings.Contains(string(output), "kernel-core"), nil

}

// GetChangelogs implements Action.
func (r *rhel) GetChangelogs(ctx context.Context, packageName string) (string, error) {
	logger.GetLogger().Info(ctx, logMsgGetChangeLogForPackage, map[string]any{"pkg-name": packageName})
	cmd := exec.CommandContext(ctx, "yum", "changelog", packageName)
	output, err := cmd.Output()
	if err != nil {
		logger.GetLogger().Error(ctx, logMsgFailedToGetChangeLogForPackage, err, map[string]any{"output": string(output)})
		return "", err
	}
	if strings.Contains(string(output), "is not installed") {
		return "", errors.New("this package is not installed")
	}
	return string(output), nil
}

// GetCurrentPackageVersion implements Action.
func (r *rhel) GetCurrentPackageVersion(ctx context.Context, packageName string) (string, error) {
	logger.GetLogger().Info(ctx, logMsgGetPackageVersion, map[string]any{"pkg-name": packageName})
	cmd := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", packageName)
	output, err := cmd.Output()
	if err != nil {
		logger.GetLogger().Error(ctx, logMsgFailedToGetPackageVersion, err, map[string]any{"output": string(output)})
		return "", err
	}
	return string(output), nil
}
