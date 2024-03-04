package constants

import "regexp"

type Distro string

const (
	DEBIAN  Distro = "debian"
	RHEL    Distro = "rhel"
	INVALID Distro = "invalid"
)

const (
	ParamCVEID = "cveID"
)

var CveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
