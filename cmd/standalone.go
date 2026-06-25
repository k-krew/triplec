package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/updater"
)

func runStandalone(cfg *config.Config, save updater.SaveFunc) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting standalone mode")

	u := updater.New(cfg, save)
	u.Start(ctx)

	slog.Info("shutdown complete")
	return nil
}
