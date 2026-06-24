# TripleC (Củ Chi Cert)

> A lightweight ACME control plane for distributing TLS certificates to air-gapped networks.

*Named after the famous Củ Chi tunnels — a vast, isolated underground network — TripleC is built on the same philosophy. It provides a secure, invisible conduit to distribute legitimate public TLS certificates deep into your air-gapped and isolated infrastructure, without exposing internal services to the internet.*

---

## Overview

TripleC is a centralized, single-binary ACME/TLS manager designed to act as a secure bridge between public certificate authorities (like Let's Encrypt) and your private infrastructure.

Instead of running full ACME clients on every internal server (which requires outbound internet access and complex DNS credential distribution), TripleC handles the heavy lifting at the edge of your network and securely pushes certificates inward.

## Features

- **Single Binary, Three Modes**: Run as a `standalone` manager, a `server` gateway, or a lightweight air-gapped `client`.
- **100+ DNS Providers**: Built on top of `go-acme/lego`, supporting native integration with Cloudflare, Route53, Google Cloud DNS, and dozens more.
- **REST API Driven**: No complex thick clients or gRPC definitions. Internal services can fetch certificates via simple HTTP REST calls.
- **Air-Gap Native**: Internal clients never touch the internet. They simply poll the TripleC server to fetch updated certificate materials.
- **Zero Database**: Simple, predictable filesystem state storage.
- **Modern Observability**: Prometheus metrics and structured JSON logs out of the box.

*(Documentation and build instructions coming soon)*
