package cve

import (
	"context"
	"fmt"
	"testing"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/mock"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"
)

type testCVETable struct {
	mockData                         []model.AppCVE
	expectedOutput                   []model.AppCVE
	numberOfErrs                     int
	failedToGetCVEIDsScoreForAllApps bool
}

func TestCVE(t *testing.T) {
	assert := require.New(t)
	defer gock.Off()
	testCfg := mock.MockConfig("../../config/config.test.yaml")
	cve := NewCVEService(testCfg)
	for _, req := range mock.MockCVEAPIResponse(testCfg) {
		gock.New(req.URL).Get(req.Path).Persist().MatchParams(req.QueryParamsMap).Reply(req.StatusCode).JSON(req.Response)
	}
	for _, mockData := range prepareMockDataForTestCVE() {
		data, failedToGetCVEIDsScoreForAllApps, errs := cve.FillAppsDataWithCVEScore(context.Background(), mockData.mockData...)
		assert.Equal(mockData.numberOfErrs, len(errs))
		assert.Equal(mockData.failedToGetCVEIDsScoreForAllApps, failedToGetCVEIDsScoreForAllApps)
		checkExpectedOutput(assert, data, mockData.expectedOutput)
	}
}

func checkExpectedOutput(assert *require.Assertions, output []model.AppCVE, expectedOutput []model.AppCVE) {
	assert.Equal(2, len(output), "lenght of output don't match")

	for i := range expectedOutput {
		fmt.Printf("test case #%d \n", i)
		assert.Equal(expectedOutput[i].CVEScore, output[i].CVEScore)
	}
}

func prepareMockDataForTestCVE() []testCVETable {
	return []testCVETable{
		{
			mockData: []model.AppCVE{
				{
					Name:  "curl",
					CVEID: []string{"CVE-2024-0853"},
				},
				{
					Name:  "foo",
					CVEID: []string{"CVE-2024-0854", "CVE-2024-0855", "CVE-2024-0856", "CVE-2024-0857"},
				},
			},
			expectedOutput: []model.AppCVE{
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
			},
			numberOfErrs: 1,
		},
		{
			mockData: []model.AppCVE{
				{
					Name:  "curl",
					CVEID: []string{"CVE-2024-0953"},
				},
				{
					Name:  "foo",
					CVEID: []string{"CVE-2024-0954", "CVE-2024-0955", "CVE-2024-0956", "CVE-2024-0957"},
				},
			},
			expectedOutput: []model.AppCVE{
				{
					Name: "curl",
				},
				{
					Name: "foo",
				},
			},
			numberOfErrs: 2,
		},
	}

}
