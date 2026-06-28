package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "triplec-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing temp file: %v", err)
	}
	return f.Name()
}

func TestLoadConfig_Valid(t *testing.T) {
	yaml := `
global:
  mode: standalone
  storage_path: /tmp/certs
  check_interval: 4h
  renew_before_days: 30

logging:
  level: debug
  format: json

issuers:
  letsencrypt:
    email: admin@example.com
    key_path: /etc/triplec/account.key
    server_url: https://acme-v02.api.letsencrypt.org/directory

certificates:
  - domains:
      - example.com
      - www.example.com
    challenge: dns-01
    issuer: letsencrypt
    provider:
      name: cloudflare
      options:
        dns_api_token: tok123
    pre_hooks:
      - echo pre
    post_hooks:
      - systemctl reload nginx
    renew_before_days: 14
`
	cfg, err := LoadConfig(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Global.Mode != ModeStandalone {
		t.Errorf("mode: got %q, want %q", cfg.Global.Mode, ModeStandalone)
	}
	if cfg.Global.StoragePath != "/tmp/certs" {
		t.Errorf("storage_path: got %q", cfg.Global.StoragePath)
	}
	if cfg.Global.CheckInterval != 4*time.Hour {
		t.Errorf("check_interval: got %v", cfg.Global.CheckInterval)
	}
	if cfg.Global.RenewBeforeDays != 30 {
		t.Errorf("renew_before_days: got %d", cfg.Global.RenewBeforeDays)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("logging.level: got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("logging.format: got %q", cfg.Logging.Format)
	}

	iss, ok := cfg.Issuers["letsencrypt"]
	if !ok {
		t.Fatal("issuer 'letsencrypt' not found")
	}
	if iss.Email != "admin@example.com" {
		t.Errorf("issuer email: got %q", iss.Email)
	}

	if len(cfg.Certificates) != 1 {
		t.Fatalf("certificates: got %d, want 1", len(cfg.Certificates))
	}
	cert := cfg.Certificates[0]
	if len(cert.Domains) != 2 {
		t.Errorf("domains: got %d", len(cert.Domains))
	}
	if cert.Challenge != "dns-01" {
		t.Errorf("challenge: got %q", cert.Challenge)
	}
	if len(cert.PreHooks) != 1 {
		t.Errorf("pre_hooks: got %d", len(cert.PreHooks))
	}
	if len(cert.PostHooks) != 1 {
		t.Errorf("post_hooks: got %d", len(cert.PostHooks))
	}
	if cert.RenewBeforeDays != 14 {
		t.Errorf("cert renew_before_days: got %d", cert.RenewBeforeDays)
	}
	if cert.Provider.Name != "cloudflare" {
		t.Errorf("provider.name: got %q", cert.Provider.Name)
	}
	if cert.Provider.Options["dns_api_token"] != "tok123" {
		t.Errorf("provider.options.dns_api_token: got %q", cert.Provider.Options["dns_api_token"])
	}
}

func TestLoadConfig_AllModes(t *testing.T) {
	base := func(mode Mode, extra string) string {
		return "global:\n  mode: " + string(mode) + "\n  storage_path: /tmp/certs\n" + extra
	}

	cases := map[Mode]string{
		ModeStandalone: base(ModeStandalone, `issuers:
  le:
    email: a@b.com
    key_path: /tmp/k
    server_url: https://acme.example.com/dir
certificates:
  - domains: [example.com]
    issuer: le
`),
		ModeServer: base(ModeServer, `server:
  listen_addr: ":8443"
  auth_token: secret
issuers:
  le:
    email: a@b.com
    key_path: /tmp/k
    server_url: https://acme.example.com/dir
certificates:
  - domains: [example.com]
    issuer: le
`),
		ModeClient: base(ModeClient, `client:
  server_url: https://triplec.internal
  auth_token: secret
certificates:
  - domains: [example.com]
    issuer: le
`),
	}

	for mode, yaml := range cases {
		t.Run(string(mode), func(t *testing.T) {
			_, err := LoadConfig(writeTemp(t, yaml))
			if err != nil {
				t.Errorf("unexpected error for mode %q: %v", mode, err)
			}
		})
	}
}

func TestLoadConfig_InvalidMode(t *testing.T) {
	yaml := "global:\n  mode: unknown\n"
	_, err := LoadConfig(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	_, err := LoadConfig(writeTemp(t, "global: [bad: yaml"))
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadConfig_EmptyModeDefaultsInvalid(t *testing.T) {
	_, err := LoadConfig(writeTemp(t, "global: {}\n"))
	if err == nil {
		t.Fatal("expected validation error when mode is empty, got nil")
	}
}

func TestLoadConfig_ServerAndClientFields(t *testing.T) {
	yaml := `
global:
  mode: server
  storage_path: /tmp/certs
server:
  listen_addr: ":8443"
  auth_token: secret
  tls_cert: /etc/triplec/tls.crt
  tls_key: /etc/triplec/tls.key
issuers:
  le:
    email: a@b.com
    key_path: /tmp/k
    server_url: https://acme.example.com/dir
certificates:
  - domains: [example.com]
    issuer: le
`
	cfg, err := LoadConfig(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.ListenAddr != ":8443" {
		t.Errorf("listen_addr: got %q", cfg.Server.ListenAddr)
	}
	if cfg.Server.AuthToken != "secret" {
		t.Errorf("auth_token: got %q", cfg.Server.AuthToken)
	}
}
