package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version is set at build time via ldflags.
	Version    = "dev"
	configPath string
)

const binaryName = "obmondo-security-exporter"

func main() {
	root := &cobra.Command{
		Use:     "obmondo-security-exporter",
		Short:   "Prometheus exporter for vulnerability scanning via Vuls",
		Version: Version,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
				Level:       logLevel(cmd),
				ReplaceAttr: durationAsText,
			})))
			slog.Info("starting exporter", "binary", binaryName, "version", Version)
		},
	}

	root.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/obmondo/security-exporter/config.yaml", "path to config file")

	root.AddCommand(serveCmd(), scanCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// logLevel is info for serve, whose log is the only sign of what a daemon is
// doing, and warn for scan, which prints a report, unless --debug is set.
func logLevel(cmd *cobra.Command) slog.Level {
	if debug, _ := cmd.Flags().GetBool("debug"); debug || cmd.Name() == "serve" {
		return slog.LevelInfo
	}
	return slog.LevelWarn
}

// durationAsText prints durations as 1h0m0s; the JSON handler would print nanoseconds.
func durationAsText(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindDuration {
		a.Value = slog.StringValue(a.Value.Duration().String())
	}
	return a
}
