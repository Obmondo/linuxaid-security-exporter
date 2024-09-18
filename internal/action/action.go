package action

import "gitea.obmondo.com/EnableIT/security-exporter/internal/constants"

var (
	logMsgCheckForSecurityUpdate = "checking for security updated"
	logMsgGetChangeLogForPackage = "getting change log for package"
	logMsgGetPackageVersion      = "Getting Version for package"
)

type Action interface {
	CheckSecurityForSecurityUpdate() (string, error)
	GetChangelogs(packageName string) (string, error)
	GetCurrentPackageVersion(packageName string) (string, error)
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
