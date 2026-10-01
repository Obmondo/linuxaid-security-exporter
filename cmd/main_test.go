package main

import (
	"log/slog"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestLogLevel(t *testing.T) {
	debugScan := scanCmd()
	if err := debugScan.Flags().Set("debug", "true"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		cmd  *cobra.Command
		want slog.Level
	}{
		{"serve", serveCmd(), slog.LevelInfo},
		{"scan", scanCmd(), slog.LevelWarn},
		{"scan --debug", debugScan, slog.LevelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logLevel(tt.cmd); got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestDurationAsText(t *testing.T) {
	got := durationAsText(nil, slog.Duration("delay", 90*time.Minute)).Value
	if got.Kind() != slog.KindString || got.String() != "1h30m0s" {
		t.Errorf("expected the string 1h30m0s, got %s %v", got.Kind(), got)
	}

	if kind := durationAsText(nil, slog.Int("cves", 3)).Value.Kind(); kind != slog.KindInt64 {
		t.Errorf("expected other values to keep their kind, got %s", kind)
	}
}
