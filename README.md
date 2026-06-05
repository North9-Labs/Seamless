<div align="center">

# Seamless

**Post-quantum reverse tunnels — expose any service through a relay you control.**

HTTP · HTTPS · Raw TCP · Hybrid X25519 + ML-KEM-768

[![CI](https://github.com/North9LLC/Seamless/actions/workflows/ci.yml/badge.svg)](https://github.com/North9LLC/Seamless/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88+-orange.svg)](#building-from-source)

</div>

---

Seamless exposes services behind NAT to the internet through a relay you control. Every byte between client and relay is encrypted end-to-end by [Seam](https://github.com/North9-Labs/Seam) — a post-quantum transport protocol built on a hybrid Noise_XX + ML-KEM-768 handshake.

```
  internet              your relay                  your machine (NAT)
  ┌──────────┐  TCP/TLS ┌──────────────────┐  UDP   ┌──────────────────┐
  │ browser  │─────────►│ seamless-relay   │◄───────│ seamless client  │
  │ curl     │ Host:foo │                  │  Seam  │                  │
  └──────────┘          │  routes by       │  (PQ)  │ → 127.0.0.1:3000 │
                        │  subdomain / port│        └──────────────────┘
                        └──────────────────┘
```

The client opens one outbound Seam connection to the relay — NAT-friendly, no port forwarding. Each inbound public connection arrives as a server-pushed stream that the client bridges to the local service.

---

## Why Seamless

- **Post-quantum by default.** Harvest-now-decrypt-later attacks cannot reach session keys — ML-KEM-768 is in the handshake, not optional.
- **Works through NAT.** Client dials out. No firewall rules, no port forwarding.
- **HTTPS on the public side.** Relay terminates TLS — bring your own cert or use `--tls-self-signed` for testing.
- **FEC on lossy links.** Seam's adaptive forward error correction keeps tunneled requests fluid on hotel Wi-Fi where TCP-based tunnels stall.
- **HTTP and raw TCP.** Route by subdomain for HTTP/HTTPS services. Expose SSH, databases, or any TCP service on a relay-assigned port.
- **Config file.** Save relay keys once (`seamless config init`), then `seamless http 3000` just works.
- **Reconnect with backoff.** Client reconnects automatically (1 s → 30 s cap) with keepalive pings so idle tunnels stay alive.

---

## Quickstart

Requires Rust 1.88+. Clone both repos side by side (Seam is a path dependency):

```bash
git clone https://github.com/North9-Labs/Seam
git clone https://github.com/North9LLC/Seamless
cd Seamless
cargo build --release
```

### 1. Start the relay

**HTTP only:**
```bash
./target/release/seamless-relay \
  --seam-addr 0.0.0.0:4443 \
  --http-addr 0.0.0.0:80 \
  --base-domain tunnel.example.com
```

**HTTP + HTTPS with your own cert:**
```bash
./target/release/seamless-relay \
  --seam-addr 0.0.0.0:4443 \
  --http-addr 0.0.0.0:80 \
  --https-addr 0.0.0.0:443 \
  --tls-cert /etc/ssl/tunnel.example.com.pem \
  --tls-key  /etc/ssl/tunnel.example.com.key \
  --base-domain tunnel.example.com
```

**Quick local test with self-signed cert:**
```bash
./target/release/seamless-relay \
  --seam-addr 0.0.0.0:4443 \
  --http-addr 0.0.0.0:8080 \
  --https-addr 0.0.0.0:8443 \
  --tls-self-signed
```

On first boot the relay generates a persistent identity and prints its public keys:

```
  seam-pubkey-x25519  <64 hex chars>
  seam-pubkey-kem     <2336 hex chars>
  connect: seamless http <port> --relay ... --x25519 ... --kem ...
```

### 2. Save relay keys (one-time setup)

Instead of pasting the full hex keys on every command, save them:

```bash
./target/release/seamless config init \
  --relay relay.example.com:4443 \
  --x25519 <64 hex chars> \
  --kem    <2336 hex chars>
```

```
  config saved → /home/user/.config/seamless/config.toml

  relay  = relay.example.com:4443
  x25519 = deadbeef...
  kem    = <1168 bytes>
```

Now `seamless http 3000` works with no extra flags.

```bash
# Show saved config
./target/release/seamless config show

# Save auth token too
./target/release/seamless config init --token my-secret-token
```

### 3. Expose an HTTP service

```bash
./target/release/seamless http 3000 --subdomain myapp
```

```
  seamless tunnel ready
    public:  https://myapp.tunnel.example.com
    local:   127.0.0.1:3000
```

### 4. Expose a raw TCP service

```bash
# SSH (remote port 2222 → local :22)
./target/release/seamless tcp 22 --remote-port 2222

ssh -p 2222 user@relay.example.com
```

### Auth tokens (recommended)

```bash
# Relay — one token per line, comments with #
echo "your-secret-token" > /etc/seamless/tokens
./target/release/seamless-relay --auth-file /etc/seamless/tokens ...

# Client — save it in config once
./target/release/seamless config init --token your-secret-token
```

---

## Demo

Run the full end-to-end demo on loopback — no relay server needed:

```bash
bash examples/local-demo.sh
```

Starts relay, registers a tunnel, serves a static file, and makes two HTTP requests through it.

---

## Deployment

**systemd** — see [systemd/README.md](systemd/README.md) and `systemd/install.sh` for the production install script.

**Docker** — single-command relay:

```bash
# From the parent directory containing both Seam/ and Seamless/
docker build -f Seamless/Dockerfile -t seamless-relay .
docker run -p 4443:4443/udp -p 80:80/tcp seamless-relay \
  --seam-addr 0.0.0.0:4443 --http-addr 0.0.0.0:80
```

Or with Docker Compose (includes a `whoami` test backend):

```bash
docker compose up relay
```

**Identity persistence** — the relay saves its key pair to `seamless-relay.json` on first boot and reloads it on restart. Keep this file out of version control — it is gitignored by default. Back it up to preserve tunnel URLs across redeployments.

---

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design and [docs/PROTOCOL.md](docs/PROTOCOL.md) for the wire format spec.

### What Seam provides vs. what Seamless adds

| Layer | Seam | Seamless |
|---|---|---|
| Crypto | Noise_XX + ML-KEM-768, ChaCha20-Poly1305, replay protection | Nothing |
| Transport | CUBIC CC, RACK-TLP loss detection, token-bucket pacer | Nothing |
| Multiplexing | `SeamMux` + `SeamStream` (AsyncRead/AsyncWrite) | Designates stream 0 as control |
| Reliability | ARQ + GF(2⁸) FEC | Nothing |
| TLS | — | Optional HTTPS ingress (rustls, BYO or self-signed cert) |
| Application | — | Register/Registered/NewConn protocol, subdomain registry, HTTP/HTTPS Host routing, TCP port listeners, client config file |

---

## Admin UI

The relay exposes an admin panel at `:8088` (default). Features:

- Live tunnel list (HTTP subdomains + TCP ports)
- Proxy route manager (static upstream forwarding with health checks)
- Access log with method/host/path/status
- Relay identity + copy-ready connect command
- Cloudflare API integration (DNS, tunnel management)

---

## Relay flags reference

| Flag | Default | Description |
|---|---|---|
| `--seam-addr` | `0.0.0.0:4443` | UDP address for Seam connections |
| `--http-addr` | `0.0.0.0:8080` | TCP address for HTTP ingress |
| `--https-addr` | — | TCP address for HTTPS ingress (requires TLS flags) |
| `--tls-cert` | — | Path to TLS certificate PEM |
| `--tls-key` | — | Path to TLS private key PEM |
| `--tls-self-signed` | `false` | Generate a self-signed cert at startup |
| `--admin-addr` | `0.0.0.0:8088` | TCP address for admin UI |
| `--base-domain` | `localhost` | Base domain for tunnel URLs |
| `--auth-file` | — | File of allowed auth tokens (one per line) |
| `--store` | `seamless-relay.json` | Path to JSON store (identity + proxy routes) |

---

## Roadmap

- Let's Encrypt / ACME automatic cert provisioning
- DNS TXT pubkey bootstrap (clients won't need hex keys even on first connect)
- Subdomain persistence across reconnects
- HTTP/2 + WebSocket passthrough verification
- Multi-client load balancing per subdomain

---

## License

Seamless is dual-licensed:

- **Open source:** [GNU Affero General Public License v3.0](LICENSE) — free for open source projects and personal use
- **Commercial:** contact [licensing@north9.org](mailto:licensing@north9.org) for proprietary, government, SaaS tunnel hosting, or OEM use

See [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) for details.
