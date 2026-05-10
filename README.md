<div align="center">

# Seamless

**Post-quantum reverse tunnels over an encrypted UDP transport.**

Expose services behind NAT through a public relay — secured by a hybrid X25519 + ML-KEM-768 handshake, no TLS required.

[![Build](https://img.shields.io/github/actions/workflow/status/yourusername/Seamless/ci.yml?branch=main)](https://github.com/yourusername/Seamless/actions)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange)](#building-from-source)

</div>

---

## What it is

Seamless lets you expose a local service (HTTP, SSH, any TCP) to the internet through a relay you control. All traffic between the client and relay is encrypted end-to-end by [Seam](https://github.com/yourusername/Seam) — a post-quantum transport protocol.

```
  internet            your relay               your laptop (behind NAT)
  ┌──────┐  TCP :80   ┌──────────────┐  UDP    ┌──────────────────────┐
  │ curl │──────────►│seamless-relay│◄────────│ seamless (client)    │
  └──────┘  Host:foo  │              │  Seam   │ forwards to          │
                      │  routes by   │  (PQ)   │ 127.0.0.1:3000       │
                      │  subdomain   │         └──────────────────────┘
                      └──────────────┘
```

## Why Seamless

- **Post-quantum by default.** Every byte between client and relay uses Seam's hybrid Noise_XX + ML-KEM-768 handshake. Harvest-now-decrypt-later attacks can't touch it.
- **NAT-friendly.** The client dials out to the relay; no port-forwarding or firewall rules needed on the origin.
- **FEC on lossy links.** Seam carries forward error correction at the transport layer; a tunneled request stays fluid on a flaky connection where TCP-based tunnels stall.
- **HTTP and raw TCP.** Route HTTP traffic by subdomain, or expose any TCP service (SSH, databases) on a relay-assigned port.

## Quickstart

Requires Rust 1.88+.

```bash
cargo build --release
```

### 1. Start the relay

```bash
./target/release/seamless-relay \
  --apex-addr 0.0.0.0:4443 \
  --http-addr 0.0.0.0:80

# On startup it prints its public keys — copy them:
#   seam-pubkey-x25519  <hex>
#   seam-pubkey-kem     <hex>
```

The relay saves its identity to `seamless-relay.json` on first boot and reloads it on restart.

### 2. Expose an HTTP service

```bash
./target/release/seamless \
  --relay <relay-ip>:4443 \
  --x25519 <hex-from-relay-log> \
  --kem    <hex-from-relay-log> \
  http 3000 --subdomain myapp

# Output:
#   seamless tunnel ready
#     public:  http://myapp.yourdomain.com
#     local:   127.0.0.1:3000
```

### 3. Expose a raw TCP service (SSH, databases)

```bash
./target/release/seamless \
  --relay <relay-ip>:4443 \
  --x25519 <hex> --kem <hex> \
  tcp 22 --remote-port 2222

# ssh -p 2222 user@<relay-ip>
```

### Auth tokens (recommended for production)

```bash
echo "your-secret-token" > /etc/seamless/tokens
./target/release/seamless-relay --auth-file /etc/seamless/tokens ...

# Client side:
./target/release/seamless --token your-secret-token ...
```

## Building from source

Seamless depends on [Seam](https://github.com/yourusername/Seam) as a path dependency. Clone both repos side by side:

```bash
git clone https://github.com/yourusername/Seam
git clone https://github.com/yourusername/Seamless
cd Seamless
cargo build --release
```

## Deployment

See [systemd/README.md](systemd/README.md) for production systemd setup, and the [Dockerfile](Dockerfile) for container deployment.

The relay stores its persistent identity (public + private keys) in `seamless-relay.json`. **Keep this file out of version control** — it is gitignored by default.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design and [docs/PROTOCOL.md](docs/PROTOCOL.md) for the control-stream wire format.

## Roadmap

- TLS termination on the public side (Let's Encrypt via rustls)
- Config file instead of CLI flags
- DNS TXT record for pubkey bootstrap (so clients don't need the hex keys on the command line)
- Subdomain reservations across client reconnects
- HTTP/2 + WebSocket passthrough verification

## License

MIT
