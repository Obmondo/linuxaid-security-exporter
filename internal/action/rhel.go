package action

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

type rhel struct{}

// CheckSecurityForSecurityUpdate implements Action.
func (*rhel) CheckSecurityForSecurityUpdate() (string, error) {
	logger.GetLogger().Info(context.Background(), logMsgCheckForSecurityUpdate, nil)
	cmd := exec.Command("yum", "--security", "check-update")
	output, err := cmd.Output()
	if err != nil && !strings.Contains(err.Error(), "exit status 100") {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get security update via YUM", err, map[string]any{"output": string(output), "stderr": exitErr.Stderr})
		}
		return "", err
	}

	return string(output), nil
}

// GetChangelogs implements Action.
func (*rhel) GetChangelogs(packageName string) (string, error) {
	logger.GetLogger().Info(context.Background(), logMsgGetChangeLogForPackage, map[string]any{"pkg-name": packageName})
	cmd := exec.Command("yum", "changelog", packageName)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "faield to get changelog", err, map[string]any{"output": string(output), "stderr": exitErr.Stderr})
		}
		return "", err
	}
	if strings.Contains(string(output), "is not installed") {
		return "", errors.New("this package is not installed")
	}
	return string(output), nil
}

// GetCurrentPackageVersion implements Action.
func (*rhel) GetCurrentPackageVersion(packageName string) (string, error) {
	logger.GetLogger().Info(context.Background(), logMsgGetPackageVersion, map[string]any{"pkg-name": packageName})
	cmd := exec.Command("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", packageName)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get package version", err, map[string]any{"output": string(output), "stderr": exitErr.Stderr})
		}
		return "", err
	}
	return string(output), nil
}

func newRhelAction() *rhel {
	return &rhel{}
}
