package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/persist"
	"github.com/kreicer/triplec/pkg/server"
	"github.com/kreicer/triplec/pkg/updater"
)

// makeServerSaveFn wraps persist.SaveCert and also updates the in-memory cache
// on the certHandler so the next API request is served without a disk read.
func makeServerSaveFn(cfg *config.Config, certHandler *server.CertHandler) updater.SaveFunc {
	return func(cert config.CertificateConfig, res *certificate.Resource) error {
		if err := persist.SaveCert(cfg.Global.StoragePath, cert, res); err != nil {
			return err
		}
		dir := persist.CertDir(cfg.Global.StoragePath, cert)
		certHandler.CacheCert(dir, res.Certificate, res.PrivateKey)
		return nil
	}
}

func runServer(cfg *config.Config, _ updater.SaveFunc) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting server mode")

	srv, mux := server.New(cfg.Server.ListenAddr, cfg.Server.AuthToken)
	certHandler := server.RegisterCertHandler(mux, cfg.Global.StoragePath, cfg.Certificates)
	save := makeServerSaveFn(cfg, certHandler)

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
				save = makeServerSaveFn(cfg, certHandler)
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
