package persist

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/logger"
)

const hookTimeout = 60 * time.Second

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

	if err := WriteAtomic(filepath.Join(dir, "cert.pem"), res.Certificate, 0o644); err != nil {
		return err
	}
	if err := WriteAtomic(filepath.Join(dir, "key.pem"), res.PrivateKey, 0o600); err != nil {
		return err
	}

	slog.Info("certificate saved", "dir", dir, "domains", logger.JoinDomains(cert.Domains))

	return RunHooks(cert.PostHooks)
}

// WriteAtomic writes data to path by writing to a randomly-named temp file in
// the same directory, setting its permissions, then renaming it atomically.
// Using a random temp name prevents collisions when two goroutines write
// different certs to the same directory concurrently.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	f, err := os.CreateTemp(dir, "*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmp := f.Name()

	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("setting permissions on %s: %w", tmp, err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", path, err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing temp file %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming %s -> %s: %w", tmp, path, err)
	}

	return nil
}

// CertDir returns the directory where certificate files for cert are stored.
// Resolution order: cert.StoragePath → globalStoragePath/primary-domain → primary-domain.
func CertDir(globalStoragePath string, cert config.CertificateConfig) string {
	if cert.StoragePath != "" {
		return cert.StoragePath
	}
	primary := ""
	if len(cert.Domains) > 0 {
		primary = strings.ReplaceAll(cert.Domains[0], "*", "_wildcard")
	}
	if globalStoragePath != "" {
		return filepath.Join(globalStoragePath, primary)
	}
	return primary
}

func resolveDir(globalStoragePath string, cert config.CertificateConfig) string {
	return CertDir(globalStoragePath, cert)
}

// RunHooks executes a list of shell commands sequentially via sh -c.
// Each hook is killed after hookTimeout (60s) to prevent a hanging script
// from blocking the renewal loop indefinitely.
func RunHooks(hooks []string) error {
	for _, h := range hooks {
		if strings.TrimSpace(h) == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
		cmd := exec.CommandContext(ctx, "sh", "-c", h)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		slog.Debug("running hook", "cmd", h)
		err := cmd.Run()
		cancel()
		if err != nil {
			return fmt.Errorf("hook %q: %w", h, err)
		}
	}
	return nil
}
