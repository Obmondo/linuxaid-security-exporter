package main

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"security-exporter/config"
	"security-exporter/internal/collector"
	"security-exporter/internal/pkgscanner"
	"security-exporter/internal/prommetrics"
)

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run as a daemon with scheduled scanning and Prometheus metrics",
		Long: `Start the security exporter in daemon mode.

Periodically scans installed packages against the Vuls server and exposes
CVE metrics via a Prometheus HTTP endpoint.`,
		RunE: runServe,
	}
}

const (
	scanTimeout     = 5 * time.Minute
	shutdownTimeout = 10 * time.Second
)

// scanState holds shared state between the cron job and the /scan HTTP handler.
type scanState struct {
	mu       sync.Mutex
	previous severityCounts
}

type severityCounts struct {
	total    int
	critical int
	high     int
	medium   int
	low      int
}

// executeScan executes a vulnerability scan, updates Prometheus metrics, and returns the result.
// It is safe for concurrent use — callers must hold ss.mu.
func executeScan(ctx context.Context, sc *pkgscanner.Scanner, coll collector.Collector) (*pkgscanner.ScanResult, error) {
	start := time.Now()
	slog.Info("starting vulnerability scan")

	result, err := sc.Scan(ctx, coll)
	if err != nil {
		prommetrics.IncrScanErrors()
		prommetrics.SetScanUp(false)
		slog.Error("scan failed", "error", err)
		return nil, err
	}

	prommetrics.SetScanUp(true)
	prommetrics.Update(result)
	prommetrics.SetScanDuration(time.Since(start).Seconds())
	prommetrics.SetLastScanTimestamp()
	slog.Info("scan completed", "cves", len(result.ScannedCves), "duration", time.Since(start))

	return result, nil
}

func runServe(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	coll, err := collector.New()
	if err != nil {
		return err
	}

	if id, ver, err := collector.DetectOS(); err == nil {
		prommetrics.SetOSSupportDates(id, ver)
	}

	sc, err := pkgscanner.New(cfg.VulsServer)
	if err != nil {
		return err
	}

	ss := &scanState{}
	retryDelay := cfg.UpstreamRetryDelay.Duration

	scanTask := func() {
		ss.mu.Lock()
		defer ss.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
		defer cancel()

		result, err := executeScan(ctx, sc, coll)
		if err != nil {
			// Exit on upstream connectivity failure so systemd restarts us
			// retryDelay is added in order to control number of restarts.
			// Currently, systemd will only restart 4 times a day in case the core issue is not addressed
			if errors.Is(err, pkgscanner.ErrUpstream) {
				slog.Error("upstream scan failure, exiting for systemd restart", "error", err, "delay", retryDelay)
				time.AfterFunc(retryDelay, func() { os.Exit(1) })
			}
			return
		}

		ss.previous = countSeverities(result)
	}

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		return err
	}

	_, err = scheduler.NewJob(
		gocron.DurationJob(cfg.ScanInterval.Duration),
		gocron.NewTask(scanTask),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithStartAt(gocron.WithStartImmediately()),
	)
	if err != nil {
		return err
	}

	randomDelay := cfg.GetRandomDelay()
	if randomDelay > 0 {
		delay := time.Duration(rand.Int63n(int64(randomDelay)))
		slog.Info("applying random startup delay", "delay", delay)
		time.Sleep(delay)
	}

	scheduler.Start()
	slog.Info("scheduler started", "interval", cfg.ScanInterval.Duration, "random_delay", cfg.GetRandomDelay())

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/scan", newScanHandler(sc, coll, ss))

	server := &http.Server{
		Addr:    cfg.ListenAddress,
		Handler: mux,
	}

	go func() {
		slog.Info("starting HTTP server", "address", cfg.ListenAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down")
	if err := scheduler.Shutdown(); err != nil {
		slog.Error("scheduler shutdown error", "error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return server.Shutdown(ctx)
}
