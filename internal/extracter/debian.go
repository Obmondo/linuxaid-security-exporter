package extracter

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

type debianExtractor struct {
	instRegex *regexp.Regexp
}

/*
	please check ./example_inputs/DEBIAN_CHANGELOG.log for sample input
*/

// ExtractCVENumberForGivenChangelog implements Extracter.
func (d *debianExtractor) ExtractCVENumberForGivenChangelog(changelog string, currentInstalledVersion string) []string {
	scopedChangeLog := d.limitSearchSpace(changelog, currentInstalledVersion)
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

func (d *debianExtractor) limitSearchSpace(changelog string, currentInstalledVersion string) string {
	if strings.Index(changelog, "\n") != -1 {
		changelog = changelog[strings.Index(changelog, "\n")+1:]
	}

	// Extract package name from the changelog
	packageIndex := strings.Index(changelog, " ")
	if packageIndex == -1 {
		logger.GetLogger().Error(context.Background(), "didn't find packageIndex", nil, nil)
		return ""
	}
	packageName := changelog[:packageIndex]

	// Split the changelog into individual entries
	entries := strings.Split(changelog, "\n\n")

	// Filter out entries before the target version
	var filteredEntries []string
	var found bool
	for i, entry := range entries {
		lines := strings.Split(entry, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, packageName) {
				found = strings.Contains(line, currentInstalledVersion)
				break
			}
		}
		if found {
			filteredEntries = append(filteredEntries, entries[:i]...)
			break
		}
	}

	return strings.Join(filteredEntries, "\n\n")
}

/*
 please check ./example_inputs/DEBIAN_UPDATE.log for sample input
*/

// ExtractAppWithSecurityUpdate implements Extracter.
func (d *debianExtractor) ExtractAppWithSecurityUpdate(text string) []model.AppCVE {
	pkgs := d.instRegex.FindAllStringSubmatch(text, -1)
	if len(pkgs) == 0 {
		return nil
	}
	appCVEs := make([]model.AppCVE, 0, len(pkgs))
	for _, pkg := range pkgs {
		appCVEs = append(appCVEs, model.AppCVE{
			Name: pkg[1],
		})
	}

	return appCVEs
}

func newDebianExtractor() Extracter {
	return &debianExtractor{
		instRegex: regexp.MustCompile(`Inst (\S+)`),
	}
}
