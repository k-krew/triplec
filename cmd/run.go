package cmd

import (
	"fmt"

	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/logger"
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

	fmt.Printf("starting in %s mode (routing not yet implemented)\n", cfg.Global.Mode)
	return nil
}
