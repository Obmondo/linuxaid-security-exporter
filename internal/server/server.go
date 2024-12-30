package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/gin-gonic/gin"
)

func Start(ctx context.Context, router *gin.Engine, host string, port int) {
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: router.Handler(),
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.GetLogger().Fatal(ctx, "err occured in server", err, nil)
		}
	}()
	<-ctx.Done()

	logger.GetLogger().Info(ctx, "shutting down server", nil)
	serverCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(serverCtx); err != nil {
		logger.GetLogger().Fatal(serverCtx, "error while shutting down Server. Initiating force shutdown...", err, nil)
	} else {
		logger.GetLogger().Info(serverCtx, "server exiting", nil)
	}
}
