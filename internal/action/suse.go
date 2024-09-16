package action

import (
	"context"
	"os/exec"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func newSuse() *suse {
	return &suse{}
}

type suse struct {
}

// CheckSecurityForSecurityUpdate implements Action.
func (s *suse) CheckSecurityForSecurityUpdate() (string, error) {
	logger.GetLogger().Info(context.Background(), logMsgCheckForSecurityUpdate, nil)

	output, err := exec.Command("zypper", "list-patches", "--cve").Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Error(context.Background(), "failed to get security update", exitErr, map[string]any{"stderr": string(exitErr.Stderr)})
		}
		return "", err
	}

	return string(output), nil

}

// GetChangelogs implements Action.
func (s *suse) GetChangelogs(packageName string) (string, error) {
	return "", nil
}

// GetCurrentPackageVersion implements Action.
func (s *suse) GetCurrentPackageVersion(packageName string) (string, error) {
	return "", nil
}
