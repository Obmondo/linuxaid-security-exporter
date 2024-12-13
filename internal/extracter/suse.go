package extracter

import (
	"strings"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
)

func newSuseExtractor() *suseExtractor {
	return &suseExtractor{appCVEMap: make(map[string][]string)}
}

type suseExtractor struct {
	appCVEMap map[string][]string
}

func (s *suseExtractor) NumberOfAppsInSystemUpdate(text string) int {
	apps := []string{}
	lines := strings.Split(text, "\n")
	for _, line := range lines[2:] {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "---") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) >= 3 {
			apps = append(apps, strings.TrimSpace(columns[2]))
		}
	}
	return len(apps)
}

// ExtractAppWithSecurityUpdate implements Extracter.
func (s *suseExtractor) ExtractAppWithSecurityUpdate(output string) []model.AppCVE {
	lines := strings.Split(output, "\n")

	splitLinesIndex := -1
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "summary") {
			if splitLinesIndex == -1 {
				splitLinesIndex = i + 1
			}
		}
	}
	if splitLinesIndex != -1 {
		lines = lines[splitLinesIndex:]
	}

	for _, line := range lines {
		parts := strings.SplitN(line, "|", 8)
		if len(parts) < 7 {
			continue
		}
		cve := strings.TrimSpace(parts[1])
		summary := strings.Split(strings.TrimSpace(parts[7]), " ")
		appName := summary[len(summary)-1]

		if _, ok := s.appCVEMap[appName]; !ok {
			s.appCVEMap[appName] = []string{cve}
			continue
		}
		s.appCVEMap[appName] = append(s.appCVEMap[appName], cve)
	}

	appCVE := make([]model.AppCVE, 0, len(s.appCVEMap))
	for appName, appCVEIDs := range s.appCVEMap {
		appCVE = append(appCVE, model.AppCVE{
			Name:     appName,
			CVEID:    appCVEIDs,
			CVEScore: []string{},
		})
	}

	return appCVE
}

// ExtractCVENumberForGivenChangelog implements Extracter.
func (s *suseExtractor) ExtractCVENumberForGivenChangelog(string, string) []string {
	return nil
}
