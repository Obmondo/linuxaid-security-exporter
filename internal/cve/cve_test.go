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
	}
}

func prepareExpectedOutput() []model.AppCVE {
	return []model.AppCVE{
		{
			Name:     "curl",
			CVEID:    []string{"CVE-2024-0853"},
			CVEScore: []string{"5.3"},
		},
		{
			Name:     "foo",
			CVEID:    []string{"CVE-2024-0854"},
			CVEScore: []string{"7.3"},
		},
		{
			Name:  "foo",
			CVEID: []string{"CVE-2024-0855"},
		},
	}
}

func prepareMockDataForTestCVE() []model.AppCVE {
	apps := []model.AppCVE{
		{
			Name:  "curl",
			CVEID: []string{"CVE-2024-0853"},
		},
		{
			Name:  "foo",
			CVEID: []string{"CVE-2024-0854"},
		},
		{
			Name:  "foo",
			CVEID: []string{"CVE-2024-0855"},
		},
	}

	return apps
}
