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
	server.RegisterCertHandler(mux, cfg.Global.StoragePath, cfg.Certificates)

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		u := updater.New(cfg, save)
		u.Start(gCtx)
		return nil
	})

	g.Go(func() error {
		return srv.Serve(gCtx, cfg.Server.TLSCert, cfg.Server.TLSKey)
	})

	if err := g.Wait(); err != nil {
		return err
	}

	slog.Info("shutdown complete")
	return nil
}
