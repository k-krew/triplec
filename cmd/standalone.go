package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/k-krew/triplec/pkg/config"
	"github.com/k-krew/triplec/pkg/updater"
)

func runStandalone(cfg *config.Config, save updater.SaveFunc) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting standalone mode")

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	updaterCtx, cancelUpdater := context.WithCancel(ctx)

	for {
		u := updater.New(cfg, save)
		go u.Start(updaterCtx)

		select {
		case <-ctx.Done():
			cancelUpdater()
			slog.Info("shutdown complete")
			return nil
		case <-sighup:
			slog.Info("SIGHUP received, reloading configuration")
			cancelUpdater()

			newCfg, err := config.LoadConfig(configFile)
			if err != nil {
				slog.Error("reloading config failed, keeping current config", "err", err)
			} else {
				cfg = newCfg
				save = makeSaveFn(cfg)
				slog.Info("configuration reloaded")
			}

			updaterCtx, cancelUpdater = context.WithCancel(ctx)
		}
	}
}
