package cve

import (
	"fmt"
	"testing"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/mock"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"
)

func TestCVE(t *testing.T) {
	assert := require.New(t)
	defer gock.Off()
	testCfg := mock.MockConfig("../../config/config.test.yaml")
	cve := NewCVEService(testCfg)
	for _, req := range mock.MockCVEAPIResponse(testCfg) {
		gock.New(req.URL).Get(req.Path).Persist().MatchParams(req.QueryParamsMap).Reply(req.StatusCode).JSON(req.Response)
	}
	data, errs := cve.FillAppsDataWithCVEScore(prepareMockDataForTestCVE()...)

	if len(errs) != 1 {
		t.Error(errs)
	}

	checkExpectedOutput(assert, data, prepareExpectedOutput())
}

func checkExpectedOutput(assert *require.Assertions, output []model.AppCVE, expectedOutput []model.AppCVE) {
	assert.Equal(len(expectedOutput), len(output), "lenght of output don't match")

	for i := range expectedOutput {
		fmt.Printf("test case #%d \n", i)
		assert.Equal(expectedOutput[i].CVEScore, output[i].CVEScore)
		assert.Equal(expectedOutput[i].CVESeverity, output[i].CVESeverity)
	}
}

func prepareExpectedOutput() []model.AppCVE {
	return []model.AppCVE{
		{
			Name:           "curl",
			CurrentVersion: "7.3",
			CVEID:          []string{"CVE-2024-0853"},
			CVEScore:       []string{"1.4"},
			CVESeverity:    []string{"LOW"},
		},
		{
			Name:           "foo",
			CurrentVersion: "10.1",
			CVEID:          []string{"CVE-2024-0854"},
			CVEScore:       []string{"7.9"},
			CVESeverity:    []string{"HIGH"},
		},
		{
			Name:           "foo",
			CurrentVersion: "10.1",
			CVEID:          []string{"CVE-2024-0855"},
		},
	}
}

func prepareMockDataForTestCVE() []model.AppCVE {
	apps := []model.AppCVE{
		{
			Name:           "curl",
			CurrentVersion: "7.3",
			CVEID:          []string{"CVE-2024-0853"},
		},
		{
			Name:           "foo",
			CurrentVersion: "10.1",
			CVEID:          []string{"CVE-2024-0854"},
		},
		{
			Name:           "foo",
			CurrentVersion: "10.1",
			CVEID:          []string{"CVE-2024-0855"},
		},
	}

	return apps
}
