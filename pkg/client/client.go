package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/logger"
)

// CertResponse mirrors the JSON payload returned by the TripleC server.
type CertResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// Client polls the TripleC server for certificate updates.
type Client struct {
	cfg    *config.Config
	http   *http.Client
	onCert OnCertFunc
}

// OnCertFunc is called when a certificate is fetched from the server.
// The caller decides whether to save it (state comparison happens in v0.4.2).
type OnCertFunc func(cert config.CertificateConfig, resp *CertResponse) error

// New creates a Client configured according to cfg.
func New(cfg *config.Config, onCert OnCertFunc) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Client.InsecureSkipVerify, //nolint:gosec // intentionally configurable
		},
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 30 * time.Second, Transport: transport},
		onCert: onCert,
	}
}

// Start runs the polling loop, waking immediately and then every CheckInterval.
// It blocks until ctx is cancelled.
func (c *Client) Start(ctx context.Context) {
	interval := c.cfg.Global.CheckInterval
	if interval <= 0 {
		interval = 4 * time.Hour
	}

	slog.Info("client polling started", "server", c.cfg.Client.ServerURL, "interval", interval)
	c.pollAll()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("client polling stopped")
			return
		case <-ticker.C:
			c.pollAll()
		}
	}
}

func (c *Client) pollAll() {
	for _, cert := range c.cfg.Certificates {
		if err := c.poll(cert); err != nil {
			slog.Warn("certificate poll failed",
				"domains", logger.JoinDomains(cert.Domains),
				"err", err,
			)
		}
	}
}

func (c *Client) poll(cert config.CertificateConfig) error {
	if len(cert.Domains) == 0 {
		return nil
	}
	primary := cert.Domains[0]
	url := strings.TrimRight(c.cfg.Client.ServerURL, "/") + "/api/v1/certs/" + primary

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Client.AuthToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		slog.Info("certificate not yet available on server, will retry",
			"domains", logger.JoinDomains(cert.Domains),
		)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from server", resp.StatusCode)
	}

	var certResp CertResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return c.onCert(cert, &certResp)
}
