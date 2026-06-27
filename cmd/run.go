package cmd

import (
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/logger"
	"github.com/kreicer/triplec/pkg/persist"
)

// Run is the central entry point after CLI parsing. It loads the config,
// initializes the logger, and routes execution to the correct operating mode.
func Run(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("--config is required")
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}

	if err := logger.Init(cfg.Logging.Level, cfg.Logging.Format); err != nil {
		return err
	}

	save := func(cert config.CertificateConfig, res *certificate.Resource) error {
		return persist.SaveCert(cfg.Global.StoragePath, cert, res)
	}

	switch cfg.Global.Mode {
	case config.ModeStandalone:
		return runStandalone(cfg, save)
	case config.ModeServer:
		return runServer(cfg, save)
	default:
		return fmt.Errorf("mode %q not yet implemented", cfg.Global.Mode)
	}
}
