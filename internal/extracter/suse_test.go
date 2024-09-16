package extracter

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var expectedAppsAndTheirCVEs = map[string][]string{
	"poppler":        {"CVE-2024-6239"},
	"libvpx":         {"CVE-2023-44488", "CVE-2023-6349", "CVE-2024-5197"},
	"python3":        {"CVE-2023-52425", "CVE-2024-0397", "CVE-2024-0450", "CVE-2024-4032"},
	"MozillaFirefox": {"CVE-2024-5688", "CVE-2024-5690", "CVE-2024-5691", "CVE-2024-5692", "CVE-2024-5693", "CVE-2024-5696", "CVE-2024-5700", "CVE-2024-5702", "CVE-2024-6600", "CVE-2024-6601", "CVE-2024-6602", "CVE-2024-6603", "CVE-2024-6604"},
}

func TestSuseExtractAppWithSecurityUpdate(t *testing.T) {
	assert := require.New(t)
	suseExtractor := newSuseExtractor()
	bytes, err := os.ReadFile("./example_inputs/SUSE_CHECK-UPDATE.log")
	assert.Nil(err)
	apps := suseExtractor.ExtractAppWithSecurityUpdate(string(bytes))
	assert.Len(apps, len(expectedAppsAndTheirCVEs))
	for _, app := range apps {
		if _, ok := expectedAppsAndTheirCVEs[app.Name]; !ok {
			t.Errorf("expected entry of given application name in map: %s", app.Name)
		}
		assert.ElementsMatch(expectedAppsAndTheirCVEs[app.Name], app.CVEID, fmt.Sprintf("expected elements to match for app :%s", app.Name))
	}

}
