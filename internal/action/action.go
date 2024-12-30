package action

import (
	"context"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
)

var (
	logMsgCheckForSecurityUpdates = "checking for security update"
	logMsgGetChangeLogForPackage  = "getting change log for package"
	logMsgGetPackageVersion       = "getting Version for package"
	logMsgCheckForUpdates         = "checking for system updates"

	logMsgFailedToGetSystemUpdates       = "failed to get system update"
	logMsgFailedToGetChangeLogForPackage = "failed to get change log for package"
	logMsgFailedToGetPackageVersion      = "failed to get current package version"
)

type Action interface {
	GetPackageUpdateList(ctx context.Context, UpdateType constants.UpdateType) (string, bool, error)
	GetChangelogs(ctx context.Context, packageName string) (string, error)
	GetCurrentPackageVersion(ctx context.Context, packageName string) (string, error)
}

func NewAction(actionType constants.Distro) Action {
	switch actionType {
	case constants.DEBIAN:
		return newDebianAction()
	case constants.RHEL:
		return newRhelAction()
	case constants.SUSE:
		return newSuse()
	}
	return nil
}
