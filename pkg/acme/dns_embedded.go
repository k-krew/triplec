package acme

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"golang.org/x/net/dns/dnsmessage"
)

const defaultDNSPort = "53"

// EmbeddedDNSProvider is a challenge.Provider that spins up a temporary UDP
// DNS server on the configured port to answer Let's Encrypt TXT queries.
type EmbeddedDNSProvider struct {
	port    string
	mu      sync.RWMutex
	records map[string]string // fqdn -> TXT value
	conn    *net.UDPConn
	done    chan struct{}
}

// NewEmbeddedDNSProvider creates a provider using the given port (defaults to "53").
func NewEmbeddedDNSProvider(port string) *EmbeddedDNSProvider {
	if port == "" {
		port = defaultDNSPort
	}
	return &EmbeddedDNSProvider{
		port:    port,
		records: make(map[string]string),
		done:    make(chan struct{}),
	}
}

func (p *EmbeddedDNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := strings.ToLower(info.FQDN)

	p.mu.Lock()
	p.records[fqdn] = info.Value
	alreadyRunning := p.conn != nil
	p.mu.Unlock()

	if !alreadyRunning {
		if err := p.start(); err != nil {
			return err
		}
	}

	slog.Info("embedded DNS: TXT record registered", "fqdn", info.FQDN)
	return nil
}

func (p *EmbeddedDNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := strings.ToLower(info.FQDN)

	p.mu.Lock()
	delete(p.records, fqdn)
	remaining := len(p.records)
	p.mu.Unlock()

	slog.Info("embedded DNS: TXT record removed", "fqdn", info.FQDN)

	if remaining == 0 {
		p.stop()
	}
	return nil
}

func (p *EmbeddedDNSProvider) start() error {
	addr, err := net.ResolveUDPAddr("udp4", ":"+p.port)
	if err != nil {
		return fmt.Errorf("resolving UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("starting embedded DNS on port %s: %w", p.port, err)
	}

	p.mu.Lock()
	p.conn = conn
	p.mu.Unlock()

	slog.Info("embedded DNS server started", "port", p.port)
	go p.serve(conn)
	return nil
}

func (p *EmbeddedDNSProvider) stop() {
	p.mu.Lock()
	conn := p.conn
	p.conn = nil
	p.mu.Unlock()

	if conn != nil {
		if err := conn.Close(); err != nil {
			slog.Debug("embedded DNS: error closing connection", "err", err)
		}
		slog.Info("embedded DNS server stopped")
	}
}

func (p *EmbeddedDNSProvider) serve(conn *net.UDPConn) {
	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		go p.handleQuery(conn, addr, buf[:n])
	}
}

func (p *EmbeddedDNSProvider) handleQuery(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	var msg dnsmessage.Message
	if err := msg.Unpack(data); err != nil {
		slog.Debug("embedded DNS: failed to unpack query", "err", err)
		return
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   msg.RecursionDesired,
			RecursionAvailable: false,
		},
		Questions: msg.Questions,
	}

	for _, q := range msg.Questions {
		if q.Type != dnsmessage.TypeTXT {
			continue
		}

		fqdn := strings.ToLower(q.Name.String())

		p.mu.RLock()
		val, ok := p.records[fqdn]
		p.mu.RUnlock()

		if !ok {
			continue
		}

		name, err := dnsmessage.NewName(fqdn)
		if err != nil {
			continue
		}

		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
				TTL:   1,
			},
			Body: &dnsmessage.TXTResource{TXT: []string{val}},
		})
	}

	out, err := resp.Pack()
	if err != nil {
		slog.Debug("embedded DNS: failed to pack response", "err", err)
		return
	}

	if _, err := conn.WriteToUDP(out, addr); err != nil {
		slog.Debug("embedded DNS: failed to write response", "err", err)
	}
}
