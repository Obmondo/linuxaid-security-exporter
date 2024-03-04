package extracter

import (
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
)

type Extracter interface {
	ExtractAppWithSecurityUpdate(string) []model.AppCVE
	ExtractCVENumberForGivenChangelog(string, string) []string
}

func NewExtractor(actionType constants.Distro) Extracter {
	switch actionType {
	case constants.DEBIAN:
		return newDebianExtractor()
	case constants.RHEL:
		return newRhelExtactor()
	}
	return nil
}
