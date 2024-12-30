package extracter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	expectedRHELOutputForExtractCVENumberForGivenChangelog = []string{"CVE-2022-43552", "CVE-2020-8177", "CVE-2019-5482"}

	expectedRHELOutForExtractSecurityUpdateApps = [][]string{
		{
			"NetworkManager",
			"NetworkManager-config-server",
			"NetworkManager-wwan",
			"bpftool",
			"buildah",
			"containernetworking-plugins",
		},
		{
			"perl-Clipboard",
		},
		{},
	}
)

const (
	expectedNumberOfAppsInRHELSystemUpdate = 105
)

func TestRHELExtractCVENumberForGivenChangelog(t *testing.T) {
	assert := require.New(t)
	extractor := newRhelExtactor()
	testRHELInputForExtractCVEFromChangeLog, err := os.ReadFile("./example_inputs/RHEL_CHANGELOG.log")
	assert.Nil(err)
	output := extractor.ExtractCVENumberForGivenChangelog(string(testRHELInputForExtractCVEFromChangeLog), "7.29.0-56")
	assert.Equal(expectedRHELOutputForExtractCVENumberForGivenChangelog, output)
}

func TestRHELExtractSecurityUpdatesApps(t *testing.T) {
	assert := require.New(t)
	extractor := newRhelExtactor()
	inputRHELForExtractSecurityUpdatesApps := readRhelCheckUpdateFilesForTest(assert)
	for i, inputRHELForExtractSecurityUpdatesApp := range inputRHELForExtractSecurityUpdatesApps {
		outputs := extractor.ExtractAppWithSecurityUpdate(inputRHELForExtractSecurityUpdatesApp)
		assert.Equal(len(expectedRHELOutForExtractSecurityUpdateApps[i]), len(outputs), fmt.Sprintf("expected length did not match actual lenght at index: %d, items: %v", i, outputs))
		for j, output := range outputs {
			assert.Equal(expectedRHELOutForExtractSecurityUpdateApps[i][j], output.Name, expectedRHELOutForExtractSecurityUpdateApps[i][j])
		}
	}

}

func TestRHELNumberOfAppsInSystemUpdate(t *testing.T) {
	assert := require.New(t)
	extractor := newRhelExtactor()
	content, err := os.ReadFile("./example_inputs/RHEL-CHECK-SYSTEM-UPDATE.log")
	assert.Nil(err)
	assert.Equal(expectedNumberOfAppsInRHELSystemUpdate, extractor.NumberOfAppsInSystemUpdate(string(content)))
}

func readRhelCheckUpdateFilesForTest(assert *require.Assertions) []string {
	var data []string
	files, err := filepath.Glob("./example_inputs/RHEL_CHECK-UPDATE-*")
	assert.Nil(err)

	assert.NotEqual(0, len(files))
	for _, file := range files {
		content, err := os.ReadFile(file)
		assert.Nil(err, fmt.Sprintf("Error reading file %s", file))
		data = append(data, string(content))
	}
	return data
}
