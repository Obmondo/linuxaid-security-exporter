package action

import (
	"context"
	"os/exec"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

func newSuse() *suse {
	return &suse{}
}

type suse struct {
}

// CheckForUpdates implements Action.
func (s *suse) GetPackageUpdateList(ctx context.Context, updateType constants.UpdateType) (string, bool, error) {
	var (
		output []byte
		err    error
	)

	switch updateType {
	case constants.UpdateTypeSecurity:
		output, err = exec.CommandContext(ctx, "zypper", "list-patches", "--cve").CombinedOutput()
		if err != nil {
			logger.GetLogger().Error(ctx, logMsgCheckForSecurityUpdates, err, map[string]any{"output": string(output)})
			return "", false, err
		}

	case constants.UpdateTypeALL:
		output, err = exec.CommandContext(ctx, "zypper", "list-updates").CombinedOutput()
		if err != nil {
			logger.GetLogger().Error(ctx, logMsgFailedToGetSystemUpdates, err, map[string]any{"output": string(output)})
			return "", false, err
		}

	}

	return string(output), strings.Contains(string(output), "kernel-default"), nil
}

func (s *suse) GetChangelogs(ctx context.Context, packageName string) (string, error) {
	return "", nil
}

func (s *suse) GetCurrentPackageVersion(ctx context.Context, packageName string) (string, error) {
	return "", nil
}
