package updater

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	legoAcme "github.com/kreicer/triplec/pkg/acme"
	"github.com/kreicer/triplec/pkg/config"
)

const defaultRenewBeforeDays = 30

// SaveFunc is called with the renewed certificate material so the persistence
// layer (v0.2.5) can write it to disk.
type SaveFunc func(cert config.CertificateConfig, res *certificate.Resource) error

// Updater runs the renewal check loop.
type Updater struct {
	cfg    *config.Config
	saveFn SaveFunc
}

// New creates an Updater. saveFn is called after each successful renewal.
func New(cfg *config.Config, saveFn SaveFunc) *Updater {
	return &Updater{cfg: cfg, saveFn: saveFn}
}

// Start runs the renewal loop in a background goroutine and blocks until ctx
// is cancelled.
func (u *Updater) Start(ctx context.Context) {
	interval := u.cfg.Global.CheckInterval
	if interval <= 0 {
		interval = 4 * time.Hour
	}

	slog.Info("updater started", "interval", interval)
	u.checkAll(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("updater stopped")
			return
		case <-ticker.C:
			u.checkAll(ctx)
		}
	}
}

func (u *Updater) checkAll(ctx context.Context) {
	for _, cert := range u.cfg.Certificates {
		if err := u.renewIfNeeded(ctx, cert); err != nil {
			slog.Error("renewal check failed", "domains", cert.Domains, "err", err)
		}
	}
}

func (u *Updater) renewIfNeeded(ctx context.Context, cert config.CertificateConfig) error {
	threshold := renewThreshold(cert, u.cfg.Global.RenewBeforeDays)

	notAfter, err := certNotAfter(cert)
	if err != nil {
		// No cert on disk yet — treat as needing immediate issuance.
		slog.Info("no existing certificate found, requesting initial issuance", "domains", cert.Domains)
	} else if time.Now().Before(notAfter.Add(-threshold)) {
		slog.Debug("certificate is current, skipping", "domains", cert.Domains, "expires", notAfter)
		return nil
	}

	slog.Info("renewing certificate", "domains", cert.Domains)

	if err := runHooks(cert.PreHooks); err != nil {
		return fmt.Errorf("pre-hook failed: %w", err)
	}

	res, err := u.obtain(ctx, cert)
	if err != nil {
		return fmt.Errorf("ACME obtain failed: %w", err)
	}

	if err := u.saveFn(cert, res); err != nil {
		return fmt.Errorf("saving certificate: %w", err)
	}

	slog.Info("certificate renewed successfully", "domains", cert.Domains)
	return nil
}

func (u *Updater) obtain(ctx context.Context, cert config.CertificateConfig) (*certificate.Resource, error) {
	issuerCfg, ok := u.cfg.Issuers[cert.Issuer]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found in config", cert.Issuer)
	}

	user, err := legoAcme.LoadOrCreateUser(issuerCfg.Email, issuerCfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading ACME user: %w", err)
	}

	if err := ensureRegistered(user, issuerCfg); err != nil {
		return nil, fmt.Errorf("ACME account registration: %w", err)
	}

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = issuerCfg.ServerURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("creating lego client: %w", err)
	}

	switch cert.Challenge {
	case "http-01":
		port := cert.Provider.Options["port"]
		if port == "" {
			port = "80"
		}
		if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", port)); err != nil {
			return nil, fmt.Errorf("setting HTTP-01 provider: %w", err)
		}
		client.Challenge.Remove(challenge.DNS01)
		client.Challenge.Remove(challenge.TLSALPN01)
	default:
		provider, err := legoAcme.NewChallengeProvider(cert)
		if err != nil {
			return nil, err
		}
		var dnsOpts []dns01.ChallengeOption
		if cert.Provider.Name == legoAcme.ProviderEmbedded || cert.Provider.Name == "" {
			dnsOpts = append(dnsOpts, dns01.DisableAuthoritativeNssPropagationRequirement())
		}
		if err := client.Challenge.SetDNS01Provider(provider, dnsOpts...); err != nil {
			return nil, fmt.Errorf("setting DNS-01 provider: %w", err)
		}
		client.Challenge.Remove(challenge.HTTP01)
		client.Challenge.Remove(challenge.TLSALPN01)
	}

	_ = ctx
	return client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: cert.Domains,
		Bundle:  true,
	})
}

// ensureRegistered registers the ACME account if not already registered,
// persisting the registration resource to a JSON file next to the key.
func ensureRegistered(user *legoAcme.User, issuerCfg config.IssuerConfig) error {
	regPath := strings.TrimSuffix(issuerCfg.KeyPath, filepath.Ext(issuerCfg.KeyPath)) + ".reg.json"

	if data, err := os.ReadFile(regPath); err == nil {
		var reg registration.Resource
		if jsonErr := json.Unmarshal(data, &reg); jsonErr == nil {
			user.SetRegistration(&reg)
			return nil
		}
	}

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = issuerCfg.ServerURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}

	user.SetRegistration(reg)

	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(regPath), 0o700); err != nil {
		return err
	}

	return os.WriteFile(regPath, data, 0o600)
}

// certNotAfter parses the first certificate PEM block from the storage path
// and returns its NotAfter time.
func certNotAfter(cert config.CertificateConfig) (time.Time, error) {
	path := certFilePath(cert)
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in %s", path)
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}

	return parsed.NotAfter, nil
}

func certFilePath(cert config.CertificateConfig) string {
	if cert.StoragePath != "" {
		return cert.StoragePath
	}
	if len(cert.Domains) > 0 {
		return filepath.Join(cert.Domains[0], "cert.pem")
	}
	return "cert.pem"
}

func renewThreshold(cert config.CertificateConfig, globalDays int) time.Duration {
	days := cert.RenewBeforeDays
	if days <= 0 {
		days = globalDays
	}
	if days <= 0 {
		days = defaultRenewBeforeDays
	}
	return time.Duration(days) * 24 * time.Hour
}

func runHooks(hooks []string) error {
	for _, h := range hooks {
		if strings.TrimSpace(h) == "" {
			continue
		}
		cmd := exec.Command("sh", "-c", h)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		slog.Debug("running hook", "cmd", h)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("hook %q: %w", h, err)
		}
	}
	return nil
}
