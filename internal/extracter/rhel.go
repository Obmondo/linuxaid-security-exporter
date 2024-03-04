package extracter

import (
	"regexp"
	"sort"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
)

type rhelExtractor struct {
	appRegex *regexp.Regexp
}

/*
 for sample input for this function please look at ./example_inputs/RHEL_CHANGELOG.log
*/

// ExtractCVENumberForGivenChangelog implements Extracter.
func (r *rhelExtractor) ExtractCVENumberForGivenChangelog(changelog string, currentInstalledVersion string) []string {
	scopedChangeLog := r.limitSearchSpace(changelog, currentInstalledVersion)
	cveIDs := constants.CveRegex.FindAllString(scopedChangeLog, -1)
	filterMap := make(map[string]struct{})

	for _, cveID := range cveIDs {
		filterMap[cveID] = struct{}{}
	}
	cveIDs = cveIDs[:0]
	for key := range filterMap {
		cveIDs = append(cveIDs, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(cveIDs)))

	return cveIDs
}

func (r *rhelExtractor) limitSearchSpace(changelog string, version string) string {
	// Split the changelog into individual entries
	entries := strings.Split(changelog, "\n")
	// Filter out entries before the target version
	var filteredEntries []string
	var startLine int
	var lastMatch int
	for i, entry := range entries {
		lines := strings.Split(entry, "\n")
		for _, line := range lines {

			if strings.Contains(line, "Available Packages") {
				startLine = i
			}

			if strings.Contains(line, version) {
				lastMatch = i
			}
		}
	}
	if lastMatch == 0 {
		lastMatch = len(entries) - 1
	}
	filteredEntries = append(filteredEntries, entries[startLine+1:lastMatch]...)

	return strings.Join(filteredEntries, "\n\n")
}

/*
	for sample input please check ./example_inputs/RHEL_CHECK-UPDATE.log
*/

// ExtractAppWithSecurityUpdate implements Extracter.
func (r *rhelExtractor) ExtractAppWithSecurityUpdate(text string) []model.AppCVE {
	lines := strings.Split(text, "\n")
	processedText := ""
	for i, line := range lines {
		if i >= 3 {
			processedText += line + "\n"
		}
	}

	pkgs := r.appRegex.FindAllStringSubmatch(processedText, -1)
	if len(pkgs) == 0 {
		return nil
	}

	appCVEs := make([]model.AppCVE, 0, len(pkgs))
	for _, pkg := range pkgs {
		appCVEs = append(appCVEs, model.AppCVE{
			Name: strings.TrimSpace(pkg[1]),
		})
	}

	return appCVEs
}

func newRhelExtactor() Extracter {
	return &rhelExtractor{
		appRegex: regexp.MustCompile(`(\S+)\.(?:x86_64|noarch)\b`),
	}
}
