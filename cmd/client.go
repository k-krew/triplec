package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kreicer/triplec/pkg/client"
	"github.com/kreicer/triplec/pkg/config"
)

func runClient(cfg *config.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting client mode")

	saveFn := client.NewSaveFunc(cfg.Global.StoragePath)
	onCert := client.NewCertHandler(cfg.Global.StoragePath, saveFn)

	c := client.New(cfg, onCert)
	c.Start(ctx)

	slog.Info("shutdown complete")
	return nil
}
