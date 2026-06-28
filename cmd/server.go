package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/server"
	"github.com/kreicer/triplec/pkg/updater"
)

func runServer(cfg *config.Config, save updater.SaveFunc) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting server mode")

	srv, mux := server.New(cfg.Server.ListenAddr, cfg.Server.AuthToken)
	certHandler := server.RegisterCertHandler(mux, cfg.Global.StoragePath, cfg.Certificates)

	// updaterCtx is cancelled on SIGHUP to restart the updater cleanly.
	updaterCtx, cancelUpdater := context.WithCancel(ctx)

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return srv.Serve(gCtx, cfg.Server.TLSCert, cfg.Server.TLSKey)
	})

	g.Go(func() error {
		for {
			u := updater.New(cfg, save)
			u.Start(updaterCtx)

			select {
			case <-gCtx.Done():
				cancelUpdater()
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
					certHandler.Update(cfg.Global.StoragePath, cfg.Certificates)
					slog.Info("configuration reloaded")
				}

				updaterCtx, cancelUpdater = context.WithCancel(gCtx)
			}
		}
	})

	if err := g.Wait(); err != nil {
		return err
	}

	slog.Info("shutdown complete")
	return nil
}
