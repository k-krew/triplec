package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeStandalone Mode = "standalone"
	ModeServer     Mode = "server"
	ModeClient     Mode = "client"
)

// Config is the top-level configuration structure.
type Config struct {
	Global       GlobalConfig            `yaml:"global"`
	Logging      LoggingConfig           `yaml:"logging"`
	Issuers      map[string]IssuerConfig `yaml:"issuers"`
	Certificates []CertificateConfig     `yaml:"certificates"`
	Server       ServerConfig            `yaml:"server"`
	Client       ClientConfig            `yaml:"client"`
}

// LoggingConfig controls log output format and verbosity.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// GlobalConfig holds settings that apply across all operating modes.
type GlobalConfig struct {
	Mode            Mode          `yaml:"mode"`
	StoragePath     string        `yaml:"storage_path"`
	CheckInterval   time.Duration `yaml:"check_interval"`
	RenewBeforeDays int           `yaml:"renew_before_days"`
}

// IssuerConfig defines an ACME account for a certificate authority.
type IssuerConfig struct {
	Email     string `yaml:"email"`
	KeyPath   string `yaml:"key_path"`
	ServerURL string `yaml:"server_url"`
}

// CertificateConfig defines a single certificate to be managed.
type CertificateConfig struct {
	Domains         []string          `yaml:"domains"`
	Challenge       string            `yaml:"challenge"`
	Issuer          string            `yaml:"issuer"`
	Provider        string            `yaml:"provider"`
	ProviderOptions map[string]string `yaml:"provider_options"`
	PreHooks        []string          `yaml:"pre_hooks"`
	PostHooks       []string          `yaml:"post_hooks"`
	StoragePath     string            `yaml:"storage_path"`
	RenewBeforeDays int               `yaml:"renew_before_days"`
}

// ServerConfig holds settings for server mode.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	AuthToken  string `yaml:"auth_token"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
}

// ClientConfig holds settings for client mode.
type ClientConfig struct {
	ServerURL string `yaml:"server_url"`
	AuthToken string `yaml:"auth_token"`
}

// LoadConfig reads and parses the YAML config file at the given path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	switch cfg.Global.Mode {
	case ModeStandalone, ModeServer, ModeClient:
	default:
		return fmt.Errorf("global.mode must be one of: standalone, server, client (got %q)", cfg.Global.Mode)
	}
	return nil
}
