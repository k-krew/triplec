package acme

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/kreicer/triplec/pkg/config"
)

const (
	ProviderEmbedded   = "embedded"
	ProviderCloudflare = "cloudflare"
)

// NewChallengeProvider returns the correct lego challenge.Provider for the
// given certificate configuration.
func NewChallengeProvider(cert config.CertificateConfig) (challenge.Provider, error) {
	opts := cert.ProviderOptions
	if opts == nil {
		opts = map[string]string{}
	}

	switch cert.Provider {
	case ProviderEmbedded, "":
		return NewEmbeddedDNSProvider(opts["port"]), nil

	case ProviderCloudflare:
		return newCloudflareProvider(opts)

	default:
		return nil, fmt.Errorf("unknown provider %q for domains %v", cert.Provider, cert.Domains)
	}
}

func newCloudflareProvider(opts map[string]string) (challenge.Provider, error) {
	cfg := cloudflare.NewDefaultConfig()
	cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}

	cfg.AuthToken = opts["dns_api_token"]
	cfg.ZoneToken = opts["zone_api_token"]
	cfg.AuthEmail = opts["email"]
	cfg.AuthKey = opts["api_key"]

	if cfg.TTL == 0 {
		cfg.TTL = 120
	}
	if cfg.PropagationTimeout == 0 {
		cfg.PropagationTimeout = 2 * time.Minute
	}
	if cfg.PollingInterval == 0 {
		cfg.PollingInterval = dns01.DefaultPollingInterval
	}

	p, err := cloudflare.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cloudflare provider: %w", err)
	}
	return p, nil
}
