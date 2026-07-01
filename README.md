![Claude Assisted](https://img.shields.io/badge/Made%20with-Claude-8A2BE2?logo=anthropic)

# TripleC (Centralized Certificate Conduit / Củ Chi Cert)

**TripleC** is a centralized, single-binary ACME/TLS manager designed to act as a secure bridge between public certificate authorities (like Let's Encrypt) and your private infrastructure.

Instead of running full ACME clients on every internal server (which requires outbound internet access and complex DNS credential distribution), TripleC handles the heavy lifting at the edge of your network and securely pushes certificates inward to air-gapped nodes.

## Features

- **Single Binary, Three Modes** - Run as a `standalone` manager, a `server` gateway, or a lightweight air-gapped `client`.
- **DNS-01 & HTTP-01 Challenges** - Native support for Cloudflare DNS and an embedded UDP DNS server for internal networks, plus built-in HTTP-01 validation.
- **REST API Driven** - Internal services can fetch certificates via simple HTTP REST calls.
- **Air-Gap Native** - Internal clients never touch the internet. They simply poll the TripleC server to fetch updated certificate materials.
- **Pre/Post Hooks** - Execute shell scripts before or after certificate updates (e.g., to reload Nginx or HAProxy).
- **Hot Reload** - Zero-downtime configuration reloads via `SIGHUP`.

## Installation

### Binary Download

Grab the latest pre-compiled binary for your OS and architecture from the [GitHub Releases](https://github.com/k-krew/triplec/releases) page and place it in your `$PATH`.

### Homebrew (macOS / Linux)

```bash
brew tap k-krew/tap
brew trust k-krew/tap
brew install --cask triplec
```

### From Source

```bash
git clone https://github.com/k-krew/triplec.git
cd triplec
go build -o triplec ./cmd/triplec
```

*(Docker images coming soon)*

## Quick Start

TripleC is designed to be run as a background service. It accepts minimal CLI flags, relying entirely on its YAML configuration file.

```bash
# Validate configuration file syntax
./triplec --test --config config.yaml

# Run the service
./triplec --config config.yaml
```

To reload the configuration without dropping active connections or restarting the process, send a `SIGHUP` signal:

```bash
kill -HUP $(pgrep triplec)
```

## Operating Modes

TripleC is configured entirely via a single YAML file. The `global.mode` specified in the configuration determines how the binary behaves.

### 1. Standalone Mode (`standalone`)
Runs as a traditional ACME client. It periodically checks certificate expiration, performs ACME challenges (DNS-01 or HTTP-01), saves the certificates to disk, and runs any configured hooks. No API is exposed.

### 2. Server Mode (`server`)
Acts as the central control plane. It performs all the duties of Standalone mode, but additionally exposes a secure REST API (`GET /api/v1/certs/{domain}`). This API serves the certificates directly from an in-memory cache to internal clients.

### 3. Client Mode (`client`)
Runs on your isolated, air-gapped nodes. It has no ACME logic and requires no internet access. It simply polls the TripleC Server via the REST API, compares the remote certificate with the local one byte-for-byte, and if an update is found, saves it atomically and triggers local hooks.

## Using the Embedded DNS Server (DNS-01)

TripleC includes an embedded UDP DNS server to seamlessly handle `dns-01` challenges without requiring API credentials for your DNS provider.

To use it, you must delegate the `_acme-challenge` subdomain to the server running TripleC so that Let's Encrypt (or your ACME CA) can query it for the required TXT records.

### 1. DNS Delegation (NS Record)

In your primary DNS zone (e.g., `example.com`), create an `NS` record pointing the `_acme-challenge` subdomain to the public hostname or IP of your TripleC server:

```text
_acme-challenge.example.com. IN NS triplec.example.com.
triplec.example.com.         IN A  203.0.113.5
```

*(If you are using an internal ACME CA like Step-CA, ensure your internal DNS resolvers forward queries for this zone to the TripleC server).*

### 2. Network Configuration

Ensure that port `53` (UDP) is open on your firewall and routed to the TripleC server so the ACME CA can reach it.

### 3. Custom Port (Optional)

If you cannot bind to port 53 directly (e.g., running as a non-root user), you can configure TripleC to listen on a custom port and use `iptables` or a load balancer to forward port 53 UDP traffic to it:

```yaml
    provider:
      name: "" # Embedded DNS
      options:
        port: "5353"
```

## Configuration Reference

TripleC is configured entirely via a single YAML file. You can find fully documented templates for each operating mode in the [`examples/`](examples/) directory:

- [`examples/config_standalone.yaml`](examples/config_standalone.yaml)
- [`examples/config_server.yaml`](examples/config_server.yaml)
- [`examples/config_client.yaml`](examples/config_client.yaml)

Below is a comprehensive configuration example showcasing all available options across different modes.

```yaml
global:
  # Operating mode: "standalone", "server", or "client"
  mode: "server"
  # Base directory where certificates and keys will be saved
  storage_path: "/var/lib/triplec/certs"
  # How often to check for renewals or poll the server (default: 4h)
  check_interval: 12h
  # How many days before expiration to trigger a renewal (default: 30)
  renew_before_days: 30

logging:
  # "debug", "info", "warn", or "error"
  level: "info"
  # "text" or "json"
  format: "text"

# Required for "server" mode
server:
  listen_addr: "0.0.0.0:8080"
  auth_token: "super-secret-bearer-token"
  # Optional: Serve the API over HTTPS
  # tls_cert: "/path/to/server.crt"
  # tls_key: "/path/to/server.key"

# Required for "client" mode
client:
  server_url: "http://triplec-server.internal:8080"
  auth_token: "super-secret-bearer-token"
  # Set to true if the server uses a self-signed TLS certificate
  insecure_skip_verify: false

# Required for "standalone" and "server" modes
issuers:
  letsencrypt-prod:
    email: "admin@example.com"
    # Path where the ACME account private key and registration JSON will be saved
    key_path: "/var/lib/triplec/accounts/le-prod.key"
    server_url: "https://acme-v02.api.letsencrypt.org/directory"

# Required for all modes
certificates:
  # Example 1: DNS-01 challenge using Cloudflare
  - domains: ["*.example.com", "example.com"]
    challenge: "dns-01"
    issuer: "letsencrypt-prod"
    provider:
      name: "cloudflare"
      options:
        # Pass credentials directly in the config
        auth_token: "your-cloudflare-api-token"
    # Execute scripts before/after saving the certificate
    pre_hooks:
      - "echo 'Preparing to update...'"
    post_hooks:
      - "systemctl reload nginx"

  # Example 2: DNS-01 challenge using the embedded UDP DNS server
  - domains: ["internal.example.local"]
    challenge: "dns-01"
    issuer: "letsencrypt-prod"
    provider:
      # An empty name defaults to the embedded DNS server
      name: ""

  # Example 3: HTTP-01 challenge
  - domains: ["web.example.com"]
    challenge: "http-01"
    issuer: "letsencrypt-prod"
    provider:
      # An empty name for http-01 defaults to the embedded HTTP server
      name: ""
      options:
        # Port to listen on for the HTTP challenge (default is 80)
        port: "8080"
    # Override the global storage path for this specific certificate
    storage_path: "/opt/custom/certs/web"
    # Override the global renewal threshold
    renew_before_days: 15
```

## Systemd Integration

A sample systemd unit file is provided in [`examples/triplec.service`](examples/triplec.service). It supports hot-reloading via `systemctl reload triplec`.

## License & Contributing

Apache 2.0 license. Contributions are welcome! Please feel free to submit a Pull Request.
