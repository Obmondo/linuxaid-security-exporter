package controller

import (
	"context"
	"net/http"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/action"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/extracter"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/metrics"
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
	output, hasKernelUpdate, numberOfPackageUpdates, err := c.getNumberOfPackageUpdates(ctx)
	if err != nil {
		logger.GetLogger().Error(ctx, "failed to get updates", err, nil)
		ctx.Abort()
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":  err,
			"output": output,
		})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"number_of_package_updates": numberOfPackageUpdates,
		"has_kernel_update":         hasKernelUpdate,
	})
}

func (c *controller) getNumberOfPackageUpdates(ctx context.Context) (string, bool, int, error) {
	output, hasKernelUpdate, err := c.action.GetPackageUpdateList(ctx, constants.UpdateTypeALL)
	if err != nil {
		return output, false, 0, err
	}

	numberOfPackageUpdates := c.extractor.NumberOfAppsInSystemUpdate(output)

	metrics.SetKernelUpdateMetricForServer(hasKernelUpdate)
	metrics.SetNumberOfPackagesWithUpdate(numberOfPackageUpdates)

	return output, hasKernelUpdate, numberOfPackageUpdates, err
}
