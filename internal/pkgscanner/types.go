package pkgscanner

import "strings"

// Package matches the vuls server's models.Package struct.
type Package struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Release         string `json:"release"`
	NewVersion      string `json:"newVersion"`
	NewRelease      string `json:"newRelease"`
	Arch            string `json:"arch"`
	Repository      string `json:"repository"`
	ModularityLabel string `json:"modularitylabel"`
}

// Packages matches the vuls server's models.Packages type.
type Packages map[string]Package

// SrcPackage represents a source package and its associated binaries.
type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

// SrcPackages maps source package names to their metadata.
type SrcPackages map[string]SrcPackage

// ScanRequest is the payload sent to the Vuls server.
type ScanRequest struct {
	Family      string      `json:"family"`
	Release     string      `json:"release"`
	ServerName  string      `json:"serverName"`
	Packages    Packages    `json:"packages"`
	SrcPackages SrcPackages `json:"srcPackages,omitempty"`
	// Optional is the vuls server's free-form metadata map, which it stores with
	// the scan result. Hosts that share one certificate — the nodes of a
	// Kubernetes cluster — put their node name here, because serverName is the
	// certificate's common name and therefore the same for all of them. The JSON
	// key is capitalised to match the field vuls persists.
	Optional map[string]any `json:"Optional,omitempty"`
}

// ScanResult is the response from the Vuls server.
type ScanResult struct {
	ServerName  string              `json:"serverName"`
	Family      string              `json:"family"`
	Release     string              `json:"release"`
	ScannedCves map[string]VulnInfo `json:"scannedCves"`
	Packages    Packages            `json:"packages"`
	SrcPackages SrcPackages         `json:"srcPackages,omitempty"`
}

type VulnInfo struct {
	CveID            string                  `json:"cveID"`
	CveContents      map[string][]CveContent `json:"cveContents"`
	AffectedPackages []AffectedPackage       `json:"affectedPackages"`
}

type CveContent struct {
	CveID         string  `json:"cveID"`
	Cvss2Score    float64 `json:"cvss2Score"`
	Cvss2Severity string  `json:"cvss2Severity"`
	Cvss3Score    float64 `json:"cvss3Score"`
	Cvss3Severity string  `json:"cvss3Severity"`
}

type AffectedPackage struct {
	Name        string `json:"name"`
	NotFixedYet bool   `json:"notFixedYet"`
	FixedIn     string `json:"fixedIn"`
	FixState    string `json:"fixState"`
}

// ParseSrcPackages parses tab-separated "src-name\tsrc-version\tbinary-name\tstatus" lines
// into a SrcPackages map, grouping binary names under each source package.
// Only entries with status starting with "ii" (fully installed) are included.
func ParseSrcPackages(raw string) SrcPackages {
	pkgs := make(SrcPackages)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		const expectedFields = 4
		parts := strings.SplitN(line, "\t", expectedFields)
		if len(parts) < expectedFields {
			continue
		}
		srcName := parts[0]
		srcVersion := parts[1]
		binName := parts[2]
		status := parts[3]
		if !strings.HasPrefix(status, "ii") {
			continue
		}
		// Strip architecture qualifier (e.g., "bind9-libs:amd64" → "bind9-libs")
		// to match Packages keys which use ${binary:Package} (no arch qualifier).
		if idx := strings.Index(binName, ":"); idx >= 0 {
			binName = binName[:idx]
		}
		if srcName == "" || binName == "" {
			continue
		}
		sp, ok := pkgs[srcName]
		if !ok {
			sp = SrcPackage{
				Name:    srcName,
				Version: srcVersion,
			}
		}
		sp.BinaryNames = append(sp.BinaryNames, binName)
		pkgs[srcName] = sp
	}
	return pkgs
}

// ParsePackages splits tab-separated "name\tstatus\tversion" lines into a Packages map.
// Only packages with status starting with "ii" (fully installed) are included.
func ParsePackages(raw string) Packages {
	pkgs := make(Packages)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		const expectedFields = 3
		parts := strings.SplitN(line, "\t", expectedFields)
		if len(parts) < expectedFields {
			continue
		}
		name := parts[0]
		status := parts[1]
		version := parts[2]
		if name == "" || !strings.HasPrefix(status, "ii") {
			continue
		}
		pkgs[name] = Package{
			Name:    name,
			Version: version,
		}
	}
	return pkgs
}
