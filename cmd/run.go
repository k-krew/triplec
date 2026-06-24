package cmd

import "fmt"

// Run is the central entry point after CLI parsing. It will read the config
// file and route execution to the correct operating mode.
func Run(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("--config is required")
	}

	fmt.Printf("starting with config: %s (routing not yet implemented)\n", configPath)
	return nil
}
