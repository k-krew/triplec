package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/k-krew/triplec/pkg/client"
	"github.com/k-krew/triplec/pkg/config"
)

func runClient(cfg *config.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting client mode")

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	clientCtx, cancelClient := context.WithCancel(ctx)

	for {
		saveFn := client.NewSaveFunc(cfg.Global.StoragePath)
		onCert := client.NewCertHandler(cfg.Global.StoragePath, saveFn)

		c := client.New(cfg, onCert)
		go c.Start(clientCtx)

		select {
		case <-ctx.Done():
			cancelClient()
			slog.Info("shutdown complete")
			return nil
		case <-sighup:
			slog.Info("SIGHUP received, reloading configuration")
			cancelClient()

			newCfg, err := config.LoadConfig(configFile)
			if err != nil {
				slog.Error("reloading config failed, keeping current config", "err", err)
			} else {
				cfg = newCfg
				slog.Info("configuration reloaded")
			}

			clientCtx, cancelClient = context.WithCancel(ctx)
		}
	}
}
