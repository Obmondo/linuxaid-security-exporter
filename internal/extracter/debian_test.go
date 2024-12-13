package extracter

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	expectedDebianOutputForExtractAppWithSecurityUpdate = []string{"docker-compose-plugin", "netbird", "netbird-ui", "teamviewer"}
	expectedDebianOutputForExtractCVE                   = []string{"CVE-2024-0853", "CVE-2023-46219", "CVE-2023-46218", "CVE-2023-38546", "CVE-2023-38545", "CVE-2023-38039"}
)

const (
	expectedNumberOfAppsInDebianSystemUpdate = 4
)

func TestDebianExtractAppWithSecurityUpdate(t *testing.T) {
	assert := require.New(t)
	debainExtractor := newDebianExtractor()
	testInputDebianForExtractAppWithSecurityUpdate, err := os.ReadFile("./example_inputs/DEBIAN_UPDATE.log")
	assert.Nil(err)
	output := debainExtractor.ExtractAppWithSecurityUpdate(string(testInputDebianForExtractAppWithSecurityUpdate))

	assert.Equal(len(expectedDebianOutputForExtractAppWithSecurityUpdate), len(output), "lenght of extracted output is not same")
	for i, app := range expectedDebianOutputForExtractAppWithSecurityUpdate {
		assert.Equal(app, output[i].Name)
	}
}

func TestDebianExtractCVENumberForGivenChangelog(t *testing.T) {
	assert := require.New(t)
	debainExtractor := newDebianExtractor()
	testInputDebianForExtractCVEFromChangelog, err := os.ReadFile("./example_inputs/DEBIAN_CHANGELOG.log")
	assert.Nil(err)
	outputs := debainExtractor.ExtractCVENumberForGivenChangelog(string(testInputDebianForExtractCVEFromChangelog), "8.4.0-1")
	assert.NotEmpty(outputs)

	assert.Equal(expectedDebianOutputForExtractCVE, outputs)
}

func TestDebianNumberOfAppsInSystemUpdate(t *testing.T) {
	assert := require.New(t)
	extractor := newDebianExtractor()
	content, err := os.ReadFile("./example_inputs/DEBIAN-CHECK-SYSTEM-UPDATE.log")
	assert.Nil(err)
	assert.Equal(extractor.NumberOfAppsInSystemUpdate(string(content)), expectedNumberOfAppsInDebianSystemUpdate)
}
