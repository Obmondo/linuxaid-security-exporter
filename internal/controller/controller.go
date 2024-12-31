package controller

import (
	"context"
	"net/http"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/action"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/extracter"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/metrics"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/model"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/gin-gonic/gin"
)

type Controller interface {
	GetNumberOfPackageUpdates(ctx *gin.Context)
}

func NewController(action action.Action, extractor extracter.Extracter) Controller {
	return &controller{action: action, extractor: extractor}
}

type controller struct {
	action    action.Action
	extractor extracter.Extracter
}

// GetNumberOfPackageUpdates implements Controller.
func (c *controller) GetNumberOfPackageUpdates(ctx *gin.Context) {
	output, errOutput, err := c.getNumberOfPackageUpdates(ctx)
	if err != nil {
		logger.GetLogger().Error(ctx, "failed to get updates", err, map[string]any{"output": errOutput.CmdOutput})
		ctx.Abort()
		ctx.JSON(http.StatusInternalServerError, errOutput)
		return
	}
	ctx.JSON(http.StatusOK, output)
}

func (c *controller) getNumberOfPackageUpdates(ctx context.Context) (*model.TotalNumberOfPackagesWithUpdateResponse, *model.CommandErrResponse, error) {
	output, hasKernelUpdate, err := c.action.GetPackageUpdateList(ctx, constants.UpdateTypeALL)
	if err != nil {
		return nil, &model.CommandErrResponse{
			CmdOutput: output,
			Error:     err,
		}, err
	}

	totalNumberOfPackagesWithUpdate := c.extractor.NumberOfAppsInSystemUpdate(output)

	metrics.SetKernelUpdateMetricForServer(hasKernelUpdate)
	metrics.SetTotalNumberOfPackagesWithUpdate(totalNumberOfPackagesWithUpdate)

	return &model.TotalNumberOfPackagesWithUpdateResponse{
		TotalNumberOfPackagesWithUpdate: totalNumberOfPackagesWithUpdate,
		HasKernelUpdate:                 hasKernelUpdate,
	}, nil, err
}
