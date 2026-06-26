package logger

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	legolog "github.com/go-acme/lego/v4/log"
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
	legolog.Logger = &slogAdapter{}
	return nil
}

// slogAdapter bridges lego's StdLogger interface to slog.
type slogAdapter struct{}

func (a *slogAdapter) Fatal(args ...any)            { slog.Error(fmt.Sprint(args...)); os.Exit(1) }
func (a *slogAdapter) Fatalln(args ...any)          { slog.Error(fmt.Sprintln(args...)); os.Exit(1) }
func (a *slogAdapter) Fatalf(f string, args ...any) { slog.Error(fmt.Sprintf(f, args...)); os.Exit(1) }
func (a *slogAdapter) Print(args ...any)            { slog.Info(fmt.Sprint(args...)) }
func (a *slogAdapter) Println(args ...any)          { slog.Info(fmt.Sprintln(args...)) }
func (a *slogAdapter) Printf(f string, args ...any) { slog.Info(fmt.Sprintf(f, args...)) }

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
