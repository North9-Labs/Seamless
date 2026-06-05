<div align="center">

# Seamless

**Self-hosted reverse tunnels — post-quantum encrypted, HTTPS-ready, no accounts required.**

HTTP · HTTPS · Raw TCP · Hybrid X25519 + ML-KEM-768

[![CI](https://github.com/North9LLC/Seamless/actions/workflows/ci.yml/badge.svg)](https://github.com/North9LLC/Seamless/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88+-orange.svg)](#building-from-source)
[![Seam v0.1.5](https://img.shields.io/badge/seam-v0.1.5-blue.svg)](https://github.com/North9-Labs/Seam)

</div>

---

Seamless exposes services behind NAT to the internet through **a relay you control** — no third-party accounts, no per-seat pricing, no traffic inspection. Every byte between client and relay is end-to-end encrypted by [Seam](https://github.com/North9-Labs/Seam), a post-quantum UDP transport with ML-KEM-768 in the handshake.

```
  internet              your relay (VPS)              your machine (NAT)
  ┌──────────┐  TLS     ┌──────────────────────┐  UDP   ┌─────────────────┐
  │ browser  │─────────►│   seamless-relay     │◄───────│   seamless      │
  │ webhook  │ HTTPS    │                      │  Seam  │   (client)      │
  │ ssh      │          │  routes by subdomain │  (PQ)  │ → local service │
  └──────────┘          └──────────────────────┘        └─────────────────┘
```

**The client dials out.** No firewall rules. No port forwarding. No relay restart when the client reconnects.

---

## Why Seamless instead of ngrok / Cloudflare Tunnel

| | Seamless | ngrok free | Cloudflare Tunnel |
|---|---|---|---|
| **Self-hosted** | ✅ your VPS | ❌ their servers | ❌ their edge |
| **Post-quantum safe** | ✅ ML-KEM-768 | ❌ | ❌ |
| **HTTPS out of the box** | ✅ BYO or self-signed | ✅ (their cert) | ✅ (their cert) |
| **Unlimited tunnels** | ✅ | ❌ 1 on free | ✅ |
| **Custom subdomains** | ✅ | ❌ paid | ✅ |
| **Raw TCP tunnels** | ✅ | ❌ paid | ❌ |
| **Traffic visible to operator** | only you | ngrok | Cloudflare |
| **Works on lossy networks** | ✅ UDP + FEC | limited | limited |
| **Cost** | VPS (~$5/mo) | free tier / paid | free |

---

## Install

```bash
git clone https://github.com/North9-Labs/Seam
git clone https://github.com/North9LLC/Seamless
cd Seamless
cargo build --release
# Binaries: target/release/seamless  target/release/seamless-relay
```

Requires Rust 1.88+. Seam must be cloned alongside Seamless (path dependency).

---

## Quickstart — 2 minutes to a live tunnel

### 1. Start the relay on your VPS

```bash
# HTTP only (simplest)
./seamless-relay \
  --seam-addr 0.0.0.0:4443 \
  --http-addr 0.0.0.0:80 \
  --base-domain tunnel.example.com

# HTTP + HTTPS with your cert
./seamless-relay \
  --seam-addr 0.0.0.0:4443 \
  --http-addr 0.0.0.0:80 \
  --https-addr 0.0.0.0:443 \
  --tls-cert /etc/ssl/certs/tunnel.example.com.pem \
  --tls-key  /etc/ssl/private/tunnel.example.com.key \
  --base-domain tunnel.example.com

# HTTPS with self-signed cert (local testing)
./seamless-relay --https-addr 0.0.0.0:8443 --tls-self-signed
```

On first boot the relay prints its public keys:

```
INFO seamless_relay: seam-pubkey-x25519  <64 hex chars>
INFO seamless_relay: seam-pubkey-kem     <2336 hex chars>
INFO seamless_relay: connect: seamless http <port> --relay ... --x25519 ... --kem ...
```

### 2. Save the relay keys (one time)

```bash
./seamless config init \
  --relay your-vps.example.com:4443 \
  --x25519 <64 hex chars> \
  --kem    <2336 hex chars>

# config saved → /home/user/.config/seamless/config.toml
#   relay  = your-vps.example.com:4443
#   x25519 = a9d493...
#   kem    = <1168 bytes>
```

From here on, **no flags needed.** The keys are saved.

### 3. Expose a service

```bash
# Local dev server on port 3000
./seamless http 3000

# With a fixed subdomain
./seamless http 3000 --subdomain myapp
#   seamless tunnel ready
#     public:  https://myapp.tunnel.example.com
#     local:   127.0.0.1:3000

# SSH access
./seamless tcp 22 --remote-port 2222
# Then: ssh -p 2222 user@your-vps.example.com
```

That's it. The tunnel stays up. If the connection drops, the client reconnects automatically with exponential backoff (1 s → 30 s) and keepalive pings keep idle NAT mappings alive.

---

## Config reference

```bash
seamless config init   --relay host:port --x25519 hex --kem hex [--token tok]
seamless config show   # print saved values
seamless config clear  # remove config

# Flags on any command override config
seamless --relay other-relay.com:4443 http 3000
```

Config file: `~/.config/seamless/config.toml`

---

## Auth tokens

Without an auth file, **anyone who can reach the relay's UDP port can register tunnels.** Lock it down:

```bash
# On the relay — one token per line, # for comments
echo "supersecrettoken" > /etc/seamless/tokens
./seamless-relay --auth-file /etc/seamless/tokens ...

# On the client — save once
./seamless config init --token supersecrettoken

# Or per-command
./seamless --token supersecrettoken http 3000
```

---

## Deployment

### systemd (production)

See [systemd/README.md](systemd/README.md) and `systemd/install.sh`.

### Docker

```bash
# Build from parent directory (Seam + Seamless side by side)
docker build -f Seamless/Dockerfile -t seamless-relay .
docker run -p 4443:4443/udp -p 80:80/tcp -p 443:443/tcp seamless-relay \
  --seam-addr 0.0.0.0:4443 \
  --http-addr 0.0.0.0:80 \
  --https-addr 0.0.0.0:443 \
  --tls-self-signed \
  --base-domain tunnel.example.com
```

Docker Compose (includes `whoami` test backend):

```bash
docker compose up relay
```

### Identity persistence

The relay saves its keypair to `seamless-relay.json` on first boot and reloads it on restart. **Back this file up** — losing it means existing clients need to re-configure with new keys.

```bash
# Keep out of git (already in .gitignore)
cp seamless-relay.json /etc/seamless/identity.json
./seamless-relay --store /etc/seamless/identity.json ...
```

---

## Relay flags

| Flag | Default | Description |
|---|---|---|
| `--seam-addr` | `0.0.0.0:4443` | UDP address for client connections |
| `--http-addr` | `0.0.0.0:8080` | TCP address for HTTP ingress |
| `--https-addr` | *(off)* | TCP address for HTTPS ingress |
| `--tls-cert` | — | TLS certificate PEM path |
| `--tls-key` | — | TLS private key PEM path |
| `--tls-self-signed` | `false` | Generate self-signed cert at startup |
| `--admin-addr` | `0.0.0.0:8088` | Admin UI and REST API |
| `--base-domain` | `localhost` | Base domain for tunnel URLs |
| `--auth-file` | *(open)* | Token allowlist file (one per line) |
| `--store` | `seamless-relay.json` | Identity and proxy routes store |

---

## Admin UI

The relay exposes an admin panel at `http://your-relay:8088`. 

- **Tunnels** — live list of all active HTTP subdomains and TCP ports
- **Proxy routes** — static upstreams with health checks (route `api.example.com` → `10.0.0.5:8080` without a client)
- **Access log** — method, host, path, status for every request
- **Identity** — relay's public keys with copy-ready connect command
- **Cloudflare** — DNS, zone, and tunnel management via CF API

---

## Security model

### What Seam protects

Every packet between client and relay is encrypted with **ChaCha20-Poly1305** (256-bit key). The handshake uses **Noise_XX + ML-KEM-768** — a hybrid construction that is secure against both classical and quantum adversaries. Traffic recorded today cannot be decrypted by a future quantum computer.

### What Seamless adds on the public side

The relay terminates TLS on the public-facing HTTP/HTTPS ingress using **rustls** (pure-Rust, no OpenSSL). Bring a real cert from Let's Encrypt, or use `--tls-self-signed` for internal/dev use.

### Trust boundary

The relay operator sees all plaintext HTTP traffic that passes through. If you don't control the relay, don't forward sensitive data over HTTP — use HTTPS so the relay only sees TLS ciphertext (it forwards the TLS stream without decrypting it when using passthrough mode, or terminates it when using `--https-addr`).

### Anti-replay and DDoS

Seam's cookie factory issues stateless challenges before allocating per-client state. Auth tokens are compared in constant time to prevent timing attacks.

---

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design document and [docs/PROTOCOL.md](docs/PROTOCOL.md) for the wire format specification.

### Layer model

| Layer | Seam handles | Seamless adds |
|---|---|---|
| Crypto | Noise_XX + ML-KEM-768, ChaCha20-Poly1305, replay window | — |
| Transport | UDP, CUBIC/BBR CC, RACK-TLP loss detection, GF(2⁸) FEC, pacing | — |
| Multiplexing | `SeamMux` + `SeamStream` (AsyncRead + AsyncWrite) | Designates stream 0 as control |
| TLS (public) | — | rustls HTTPS ingress (BYO cert or self-signed) |
| Application | — | Register/Registered/NewConn protocol, subdomain registry, HTTP Host routing, TCP port listeners, client config file |

Seamless is intentionally thin. All the hard work lives in Seam.

---

## Roadmap

- Let's Encrypt / ACME automatic cert provisioning (no manual cert management)
- DNS TXT pubkey bootstrap (skip `--x25519`/`--kem` flags on first connect)
- Subdomain persistence across reconnects
- HTTP/2 + WebSocket passthrough verification
- Multi-client load balancing per subdomain

---

## Building from source

```bash
git clone https://github.com/North9-Labs/Seam
git clone https://github.com/North9LLC/Seamless
cd Seamless
cargo build --release
./target/release/seamless-relay --help
./target/release/seamless --help
```

Tests:

```bash
cargo test --workspace
```

---

## License

Seamless is dual-licensed:

- **Open source:** [GNU Affero General Public License v3.0](LICENSE) — free for open source projects and personal use
- **Commercial:** contact [licensing@north9.org](mailto:licensing@north9.org) for proprietary, SaaS tunnel hosting, government, or OEM use

See [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) for details.
