package cmd

import (
	"fmt"

	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/updater"
)

func runStandalone(cfg *config.Config, save updater.SaveFunc) error {
	_ = save
	return fmt.Errorf("standalone mode: not yet implemented")
}
