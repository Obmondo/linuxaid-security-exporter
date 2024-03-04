package logger

import (
	"context"
	"log"
	"log/slog"
	"os"
	"runtime"
	"strconv"
)

var localLogger *logger

type Logger interface {
	Info(ctx context.Context, msg string, params map[string]any)
	Debug(ctx context.Context, msg string, params map[string]any)
	Error(ctx context.Context, msg string, err error, params map[string]any)
	Fatal(ctx context.Context, msg string, err error, params map[string]any)
}

type logger struct {
	log *slog.Logger
}

func (l *logger) Fatal(ctx context.Context, msg string, err error, params map[string]any) {
	if err != nil {
		l.log.ErrorContext(ctx, msg, slog.Any("error", err), slog.Any("params", params), l.runTimeCaller())
		os.Exit(1)
	}
	l.log.ErrorContext(ctx, msg, slog.Any("params", params), l.runTimeCaller())
	os.Exit(1)
}

func (l *logger) Error(ctx context.Context, msg string, err error, params map[string]any) {
	l.log.ErrorContext(ctx, msg, slog.Any("error", err), slog.Any("params", params), l.runTimeCaller())
}

func (l *logger) Info(ctx context.Context, msg string, params map[string]any) {
	l.log.InfoContext(ctx, msg, slog.Any("params", params))
}

func (l *logger) Debug(ctx context.Context, msg string, params map[string]any) {
	l.log.DebugContext(ctx, msg, slog.Any("params", params))
}

func (l *logger) runTimeCaller() slog.Attr {
	_, file, line, _ := runtime.Caller(2)
	stackTrace := slog.Attr{
		Key:   "stacktrace",
		Value: slog.AnyValue(file + ":" + strconv.Itoa(line)),
	}
	return stackTrace
}

func GetLogger() Logger {
	if localLogger != nil {
		return localLogger
	}
	level := os.Getenv("LOGGING_LEVEL")
	loggingLevel := new(slog.LevelVar) // Info by default
	if level != "" {
		if err := loggingLevel.UnmarshalText([]byte(level)); err != nil {
			log.Fatal(err)
		}
	}

	structedLog := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: loggingLevel}))
	localLogger = &logger{log: structedLog}
	return localLogger
}
