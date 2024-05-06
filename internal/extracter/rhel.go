package extracter

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
)

type rhelExtractor struct {
	versionMap map[string]bool
	appRegex   *regexp.Regexp
	ignoreArow *regexp.Regexp
}

func fillVersionMap() map[string]bool {
	versionMap := make(map[string]bool)
	for i := 0; i < 10; i++ {
		versionMap[strconv.Itoa(i)] = true
	}
	return versionMap
}

/*
 for sample input for this function please look at ./example_inputs/RHEL_CHANGELOG.log
*/

// ExtractCVENumberForGivenChangelog implements Extracter.
func (r *rhelExtractor) ExtractCVENumberForGivenChangelog(changelog string, currentInstalledVersion string) []string {
	logger.GetLogger().Info(context.Background(), logMsgExtractCVENumber, nil)
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
	logger.GetLogger().Info(context.Background(), logMsgExtractAppsWithSecurityUpdate, nil)

	lines := strings.Split(text, "\n")
	processedText := ""
	for i, line := range lines {
		if i >= 3 && !r.ignoreArow.MatchString(line) {
			processedText += line + "\n"
		}
	}

	pkgs := r.appRegex.FindAllStringSubmatch(processedText, -1)
	if len(pkgs) == 0 {
		return nil
	}

	appCVEs := make([]model.AppCVE, 0, len(pkgs))
	for _, pkg := range pkgs {
		name := strings.TrimSpace(pkg[1])
		lastHyphenIndex := r.findHyphenIndexs(name)
		if lastHyphenIndex != -1 {

			appCVEs = append(appCVEs, model.AppCVE{
				Name: name[:lastHyphenIndex],
			})
			continue
		}

		appCVEs = append(appCVEs, model.AppCVE{
			Name: name,
		})
	}

	return appCVEs
}

func (r *rhelExtractor) findHyphenIndexs(str string) int {
	hyphenIndexes := []int{}

	for i, char := range str {
		if char == '-' {
			hyphenIndexes = append(hyphenIndexes, i)
		}
	}

	for _, index := range hyphenIndexes {
		if index+2 < len(str) && r.versionMap[string(str[index+1:index+2])] {
			return index
		}
	}

	return -1
}
func newRhelExtactor() Extracter {
	return &rhelExtractor{
		versionMap: fillVersionMap(),
		appRegex:   regexp.MustCompile(`(\S+)\.(?:x86_64|noarch|i686)\b`),
		ignoreArow: regexp.MustCompile(`^\s*-->.*$`),
	}
}
