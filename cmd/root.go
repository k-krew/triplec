package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/k-krew/triplec/pkg/config"
)

const version = "0.1.0-dev"

var configFile string

var rootCmd = &cobra.Command{
	Use:   "triplec",
	Short: "Centralized ACME/TLS manager for air-gapped networks",
	Long: `TripleC (Củ Chi Cert) is a single-binary ACME/TLS manager that acts as a
secure conduit between public certificate authorities and private infrastructure.

Configure the operating mode (standalone, server, or client) in the YAML config file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if v, _ := cmd.Flags().GetBool("version"); v {
			fmt.Println("triplec", version)
			return nil
		}
		if t, _ := cmd.Flags().GetBool("test"); t {
			if configFile == "" {
				return fmt.Errorf("--config is required")
			}
			if _, err := config.LoadConfig(configFile); err != nil {
				return err
			}
			fmt.Println("configuration is valid")
			return nil
		}
		return Run(configFile)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&configFile, "config", "", "path to config file (required)")
	rootCmd.Flags().Bool("version", false, "print version and exit")
	rootCmd.Flags().BoolP("test", "t", false, "validate config file and exit")
}
