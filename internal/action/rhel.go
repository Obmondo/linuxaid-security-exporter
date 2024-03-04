package action

import (
	"context"
	"os/exec"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

type rhel struct{}

// CheckSecurityForSecurityUpdate implements Action.
func (*rhel) CheckSecurityForSecurityUpdate() (string, error) {
	cmd := exec.Command("yum", "--security", "check-update")
	output, err := cmd.Output()
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to get security update via YUM", err, map[string]any{"output": string(output)})
		return "", err
	}

	return string(output), nil
}

// GetChangelogs implements Action.
func (*rhel) GetChangelogs(packageName string) (string, error) {
	cmd := exec.Command("yum", "changelog", packageName)
	output, err := cmd.Output()
	if err != nil {
		logger.GetLogger().Error(context.Background(), "faield to get changelog", err, map[string]any{"output": string(output)})
		return "", err
	}
	return string(output), nil
}

// GetCurrentPackageVersion implements Action.
func (*rhel) GetCurrentPackageVersion(packageName string) (string, error) {
	cmd := exec.Command("yum", "info", packageName)
	output, err := cmd.Output()
	if err != nil {
		logger.GetLogger().Error(context.Background(), "failed to get package version", err, map[string]any{"output": string(output)})
		return "", err
	}
	return string(output), nil
}

func newRhelAction() *rhel {
	return &rhel{}
}
