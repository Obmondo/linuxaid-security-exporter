package constants

import "regexp"

type Distro string

const (
	DEBIAN  Distro = "debian"
	RHEL    Distro = "rhel"
	SUSE    Distro = "suse"
	INVALID Distro = "invalid"
)

type UpdateType string

const (
	UpdateTypeALL      = "all"
	UpdateTypeSecurity = "security"
)

const (
	ParamCVEID = "cveID"
)

var CveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

const (
	RunTypeTest = "testing"
)

const (
	Certname    = "certname"
	Application = "application"
	CveID       = "cve_id"
	Score       = "score"
)

var CveDetailsLabels = []string{Application, CveID, Score}
