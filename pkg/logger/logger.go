package logger

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Format controls the output format of the logger.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Init initializes the global slog logger with the given level and format.
// After calling Init, use slog.Info, slog.Error, etc. throughout the application.
func Init(level, format string) error {
	slogLevel, err := parseLevel(level)
	if err != nil {
		return err
	}

	opts := &slog.HandlerOptions{Level: slogLevel}

	var handler slog.Handler
	switch Format(strings.ToLower(format)) {
	case FormatJSON:
		handler = slog.NewJSONHandler(os.Stderr, opts)
	case FormatText, "":
		handler = slog.NewTextHandler(os.Stderr, opts)
	default:
		return fmt.Errorf("log format must be %q or %q (got %q)", FormatText, FormatJSON, format)
	}

	slog.SetDefault(slog.New(handler))
	return nil
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("log level must be one of: debug, info, warn, error (got %q)", level)
	}
}
