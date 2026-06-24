package logger

import (
	"log/slog"
	"testing"
)

func TestInit_Defaults(t *testing.T) {
	if err := Init("", ""); err != nil {
		t.Fatalf("Init with empty strings: %v", err)
	}
}

func TestInit_ValidLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "warning", "error", "DEBUG", "INFO"} {
		if err := Init(level, "text"); err != nil {
			t.Errorf("Init(%q, text): unexpected error: %v", level, err)
		}
	}
}

func TestInit_ValidFormats(t *testing.T) {
	for _, format := range []string{"text", "json", "TEXT", "JSON"} {
		if err := Init("info", format); err != nil {
			t.Errorf("Init(info, %q): unexpected error: %v", format, err)
		}
	}
}

func TestInit_InvalidLevel(t *testing.T) {
	if err := Init("verbose", "text"); err == nil {
		t.Fatal("expected error for unknown level, got nil")
	}
}

func TestInit_InvalidFormat(t *testing.T) {
	if err := Init("info", "logfmt"); err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

func TestInit_SetsGlobalLogger(t *testing.T) {
	before := slog.Default()
	if err := Init("debug", "json"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	after := slog.Default()
	if before == after {
		t.Error("expected global logger to be replaced after Init")
	}
}
