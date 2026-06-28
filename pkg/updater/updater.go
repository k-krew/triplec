package updater

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	legoAcme "github.com/kreicer/triplec/pkg/acme"
	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/logger"
	"github.com/kreicer/triplec/pkg/persist"
)

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
			slog.Error("renewal check failed", "domains", logger.JoinDomains(cert.Domains), "err", err)
		}
	}
}

func (u *Updater) renewIfNeeded(ctx context.Context, cert config.CertificateConfig) error {
	threshold := renewThreshold(cert, u.cfg.Global.RenewBeforeDays)

	certPath := filepath.Join(persist.CertDir(u.cfg.Global.StoragePath, cert), "cert.pem")
	existing, err := parseCert(certPath)
	domains := logger.JoinDomains(cert.Domains)
	attrs := []any{
		"domains", domains,
		"challenge", cert.Challenge,
		"provider", cert.Provider.Name,
		"issuer", cert.Issuer,
	}

	if err != nil {
		slog.Info("no existing certificate found, requesting initial issuance", attrs...)
	} else if domainsChanged(existing, cert.Domains) {
		slog.Info("domain list changed, renewing certificate", attrs...)
	} else if time.Now().Before(existing.NotAfter.Add(-threshold)) {
		slog.Debug("certificate is current, skipping", "domains", domains, "expires", existing.NotAfter)
		return nil
	}

	slog.Info("renewing certificate", attrs...)

	if err := persist.RunHooks(cert.PreHooks); err != nil {
		return fmt.Errorf("pre-hook failed: %w", err)
	}

	res, err := u.obtain(ctx, cert)
	if err != nil {
		return fmt.Errorf("ACME obtain failed: %w", err)
	}

	if err := u.saveFn(cert, res); err != nil {
		return fmt.Errorf("saving certificate: %w", err)
	}

	slog.Info("certificate renewed successfully", attrs...)
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
	default:
		provider, err := legoAcme.NewChallengeProvider(cert)
		if err != nil {
			return nil, err
		}
		var dnsOpts []dns01.ChallengeOption
		if cert.Provider.Name == legoAcme.ProviderEmbedded || cert.Provider.Name == "" {
			// Skip all local DNS propagation checks for the embedded provider,
			// which answers queries directly and shouldn't be queried via public resolvers.
			dnsOpts = append(dnsOpts, dns01.PropagationWait(0, true))
		}
		if err := client.Challenge.SetDNS01Provider(provider, dnsOpts...); err != nil {
			return nil, fmt.Errorf("setting DNS-01 provider: %w", err)
		}
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

	return persist.WriteAtomic(regPath, data, 0o600)
}

// parseCert reads and parses the first certificate PEM block from path.
func parseCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert, nil
}

// domainsChanged reports whether the certificate's DNS SANs differ from the
// requested domain list.
func domainsChanged(cert *x509.Certificate, requested []string) bool {
	if len(cert.DNSNames) != len(requested) {
		return true
	}
	existing := make(map[string]struct{}, len(cert.DNSNames))
	for _, d := range cert.DNSNames {
		existing[strings.ToLower(d)] = struct{}{}
	}
	for _, d := range requested {
		if _, ok := existing[strings.ToLower(d)]; !ok {
			return true
		}
	}
	return false
}

func renewThreshold(cert config.CertificateConfig, globalDays int) time.Duration {
	days := cert.RenewBeforeDays
	if days <= 0 {
		days = globalDays
	}
	// globalDays is always set to DefaultRenewBeforeDays by setDefaults in config.
	return time.Duration(days) * 24 * time.Hour
}

