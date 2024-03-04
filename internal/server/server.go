package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Start(done chan os.Signal) {
	server := &http.Server{
		Addr:    ":8080",
		Handler: promhttp.Handler(),
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.GetLogger().Fatal(context.Background(), "err occured in server", err, nil)
		}
	}()
	<-done

	logger.GetLogger().Info(context.Background(), "shutting down server", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.GetLogger().Fatal(ctx, "error while shutting down Server. Initiating force shutdown...", err, nil)
	} else {
		logger.GetLogger().Info(ctx, "server exiting", nil)
	}
}
