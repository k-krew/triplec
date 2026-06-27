package persist

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/logger"
)

// SaveCert writes the certificate bundle and private key from res to disk,
// then runs any configured post-renewal hooks.
//
// Storage path resolution (first non-empty wins):
//  1. cert.StoragePath
//  2. globalStoragePath / primary-domain
func SaveCert(globalStoragePath string, cert config.CertificateConfig, res *certificate.Resource) error {
	dir := resolveDir(globalStoragePath, cert)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating storage directory %s: %w", dir, err)
	}

	if err := writeAtomic(filepath.Join(dir, "cert.pem"), res.Certificate, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "key.pem"), res.PrivateKey, 0o600); err != nil {
		return err
	}

	slog.Info("certificate saved", "dir", dir, "domains", logger.JoinDomains(cert.Domains))

	return runHooks(cert.PostHooks)
}

// writeAtomic writes data to path by first writing to a temporary file in the
// same directory and then renaming it, so the operation is atomic.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("creating temp file %s: %w", tmp, err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing temp file %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s -> %s: %w", tmp, path, err)
	}

	return nil
}

func CertDir(globalStoragePath string, cert config.CertificateConfig) string {
	if cert.StoragePath != "" {
		return cert.StoragePath
	}
	primary := ""
	if len(cert.Domains) > 0 {
		primary = cert.Domains[0]
	}
	if globalStoragePath != "" {
		return filepath.Join(globalStoragePath, primary)
	}
	return primary
}

func resolveDir(globalStoragePath string, cert config.CertificateConfig) string {
	return CertDir(globalStoragePath, cert)
}

func runHooks(hooks []string) error {
	for _, h := range hooks {
		if strings.TrimSpace(h) == "" {
			continue
		}
		cmd := exec.Command("sh", "-c", h)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		slog.Debug("running post-hook", "cmd", h)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("post-hook %q: %w", h, err)
		}
	}
	return nil
}
