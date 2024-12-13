package controller

import (
	"net/http"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/action"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/extracter"
	"gitea.obmondo.com/EnableIT/security-exporter/internal/metrics"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/gin-gonic/gin"
)

type Controller interface {
	GetTotalNumberOfAppsWithUpdates(ctx *gin.Context)
}

func NewController(action action.Action, extractor extracter.Extracter) Controller {
	return &controller{action: action, extractor: extractor}
}

type controller struct {
	action    action.Action
	extractor extracter.Extracter
}

// GetTotalNumberOfAppsWithUpdates implements Controller.
func (c *controller) GetTotalNumberOfAppsWithUpdates(ctx *gin.Context) {

	output, hasKernelUpdate, err := c.action.GetPackageUpdateList(ctx, constants.UpdateTypeALL)
	if err != nil {
		logger.GetLogger().Error(ctx, "failed to find security update", err, nil)
		ctx.Abort()
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":  err,
			"output": output,
		})
		return
	}

	metrics.SetKernelUpdateMetricForServer(hasKernelUpdate)

	ctx.JSON(http.StatusOK, gin.H{
		"total_apps_with_updates": c.extractor.NumberOfAppsInSystemUpdate(output),
		"has_kernel_update":       hasKernelUpdate,
	})
}
