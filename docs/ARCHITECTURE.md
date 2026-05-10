# Architecture

## Goals

- Reverse tunnels: expose a service that lives behind NAT to the public
  internet, through a relay the service's owner controls.
- Post-quantum by default. Every byte on the wire between client and relay
  is protected by Seam's hybrid Noise_XX + ML-KEM-768 handshake.
- Be small. One relay binary, one client binary, under a thousand lines of
  Seamless-specific code.

## Non-goals

- Not a load balancer. One subdomain maps to one client at a time.
- Not a CDN. The relay terminates nothing and caches nothing.
- Not a VPN. Seamless tunnels one service; it does not route arbitrary traffic.
- Not a secrets manager. Auth tokens (when enabled) are plain strings in a
  file the operator controls.

## Component topology

```
    end user            relay host                    origin host (NAT)
  ┌─────────┐       ┌───────────────┐               ┌───────────────┐
  │  curl / │  TCP  │seamless-relay │     Seam      │   seamless    │
  │ browser │──────►│               │◄──────────────│   (client)    │
  └─────────┘ :8080 │ ┌───────────┐ │  UDP :4443    │               │
                    │ │  router   │ │    (PQ)       │   dials       │
                    │ │           │ │               │  127.0.0.1    │
                    │ │ subdomain │ │               │   :<port>     │
                    │ │ → SeamMux │ │               │               │
                    │ └───────────┘ │               └───────────────┘
                    └───────────────┘
```

The client owns the only outbound connection. All public traffic arrives at
the relay's TCP or UDP ingress and is dispatched to whichever client has
registered the matching subdomain or port.

## What Seam provides vs. what Seamless adds

| Layer | Seam gives you | Seamless adds |
|---|---|---|
| Crypto | Noise_XX + ML-KEM-768 hybrid handshake, ChaCha20-Poly1305 packet encryption, header protection, replay window | Nothing cryptographic |
| Transport | UDP with CUBIC/BBR congestion control, RACK-TLP loss detection, pacing | Nothing transport |
| Multiplexing | `SeamMux` dispatcher + `SeamStream` AsyncRead/AsyncWrite adapters, priority-scheduled streams | Designates stream 0 as control, all others as data |
| Reliability | ARQ + GF(2⁸) forward error correction | Nothing reliability-level |
| Application | — | Control-frame protocol (Register/Registered/NewConn/Error), subdomain registry, HTTP Host-header routing, per-tunnel TCP listeners, pubkey bootstrap UX |

Seamless is a thin application on top of Seam's `tunnel` module. The heavy
work — crypto, congestion control, reassembly — lives in Seam.

## Life of a request

1. `seamless-relay` starts, generates an `IdentityKeypair` (ephemeral per run),
   logs its X25519 and ML-KEM-768 public keys on stdout.
2. `seamless http 3000 --relay <addr> --x25519 <hex> --kem <hex> --subdomain foo`
   launches on the origin box. It does a Seam hybrid handshake to the
   relay (~10 ms local, ~1 RTT over the internet).
3. The client opens its first Seam stream. This is the control stream by
   convention. It sends a `Register { version, token, kind: Http { subdomain } }`
   frame, length-prefixed with 4 big-endian bytes.
4. The relay's per-connection task calls `mux.accept_stream()`, receives
   the control stream, decodes the `Register`, checks auth (if
   `--auth-file` is set), inserts `subdomain → Arc<SeamMux>` into its
   `HashMap`, and replies with `Registered { public_url }`.
5. A public user makes `curl http://foo.example.com:8080/`. The relay
   accepts the TCP connection, reads up to 2 KiB, scans for the `Host:`
   header, strips the `:port`, strips the base-domain suffix, and looks up
   the subdomain in the registry.
6. The relay calls `mux.open_stream().await` to get a new `SeamStream`,
   writes a `NewConn { peer_addr }` preamble frame into it, then writes
   the bytes already consumed from the public TCP socket, then enters
   `copy_bidirectional(tcp, seam)`.
7. On the origin, the client's `mux.accept_stream()` hands it the new
   stream. It reads the preamble, dials `127.0.0.1:3000`, and enters
   its own `copy_bidirectional(local_tcp, seam)`.

## Identity and trust model

Today each relay process generates a fresh `IdentityKeypair` on boot and
prints its public components. Clients paste those pubkeys on their
command line. Implications:

- **No key continuity.** A relay restart invalidates every client config.
  A persistent identity file is a near-term roadmap item.
- **No CA.** Trust on first use — the operator is expected to copy the
  pubkeys out of band, same trust model as SSH.
- **Relay operator is trusted.** The public side of the relay is plaintext
  TCP; a malicious relay operator sees all tunneled HTTP request bodies.
  If you don't control the relay, don't forward plaintext through it.

## Concurrency model

- One tokio task per accepted Seam connection on the relay
  (`handle_client`). It owns the control stream and the subdomain
  registration lifecycle.
- One tokio task per public TCP connection on the relay (`route_http`).
  It parses the Host header and bridges to a `SeamStream`.
- `SeamMux` spawns its own background dispatcher that demuxes
  `SessionEvent`s onto per-stream inboxes.
- On the client, one task per `accept_stream` spawn. Each dials the local
  target and runs `copy_bidirectional` to completion.
- Shared state is an `Arc<Mutex<HashMap<Subdomain, Arc<SeamMux>>>>`. Lock
  scope is tight: clone the `Arc<SeamMux>` out under the lock, then drop
  the guard before any await on the stream.

## Failure modes and backpressure

- **Client drops.** `SeamMux::accept_stream` returns `None`, control
  stream read returns 0, `handle_client` cleans up the subdomain, public
  requests for it get a 502.
- **Slow origin.** `SeamStream` write backpressure propagates through
  Seam's per-stream flow control to the relay, and from the relay into
  `copy_bidirectional`, which stops reading from the public TCP socket
  once its write to Seam blocks. This then propagates through the kernel
  socket buffer to the end-user peer.
- **Relay overload.** No admission control today; a flood of registrations
  can exhaust memory via the subdomain HashMap and the per-connection
  tasks. Auth tokens are the first line of defense.
- **Handshake DDoS.** Seam's cookie factory issues stateless cookie
  challenges on the first message of the handshake; state is allocated
  only after the cookie is echoed back.

## Security considerations

- **Harvest-now-decrypt-later is mitigated** by the ML-KEM-768 half of the
  handshake: a future quantum adversary who recorded the ciphertext today
  cannot derive the session key.
- **Replay** is rejected by Seam's per-connection 1024-bit replay window.
- **Public side is plaintext TCP** today — users curl
  `http://foo.example.com:8080`, not https. TLS termination on the public
  side is a roadmap item (expected: rustls + Let's Encrypt in the relay).
- **Unauthenticated registration** with no `--auth-file` means anyone who
  can reach the relay over UDP can squat subdomains. Deploy with an auth
  file in any real environment.

## Roadmap pointers

See the Roadmap section of the top-level [README](../README.md). The big
near-term items are TCP tunnels (today stubbed to a 501 Error frame),
persistent relay identity, TLS on the public side, and DNS-TXT pubkey
bootstrap so clients don't need to paste 2.3 KB of Kyber key on the
command line.
