package action

import "gitea.obmondo.com/EnableIT/security-exporter/internal/constants"

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
	}
	return nil
}
