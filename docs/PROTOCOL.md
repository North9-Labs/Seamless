# Seamless Protocol Specification

Protocol version: **1** (`PROTOCOL_VERSION = 1` in `seamless-common`).

## Scope

This document specifies the application-layer protocol Seamless uses on top of
Seam streams. Seam itself — handshake, packet encryption, congestion
control, stream scheduling — is out of scope here. From Seamless's point of
view a Seam stream is a reliable, in-order, bidirectional, authenticated
byte stream with back-pressure.

## Framing

Every frame on the control stream is:

```
  +--------+--------+--------+--------+=================...
  |            u32 big-endian         |   bincode-serialized body
  |               length              |
  +--------+--------+--------+--------+=================...
```

- `length` is the body length in bytes, big-endian.
- `body` is a `bincode`-serialized `ControlFrame` value (default bincode
  config: little-endian, fixint).
- `length` must be ≤ `MAX_FRAME_BYTES = 65536`. Readers MUST reject a
  larger length and close the connection with an `Error { code: 400 }`.

## Streams

| Stream | Opened by | Carries |
|---|---|---|
| First (lowest ID on the Seam wire) | Client | Control frames only |
| All others | Relay | Data streams: one `NewConn` preamble frame, then raw tunneled bytes |

The "first stream" rule is positional — the relay identifies the control
stream as whatever it receives from its first `mux.accept_stream()` call
on a given connection.

Data streams MUST NOT carry `Register`, `Registered`, or `Error` frames.
Control streams MUST NOT carry `NewConn` frames (the `NewConn` variant
is reused from the same enum purely to give the client one decoder; the
discriminant still uniquely identifies the frame).

## Frame catalogue

All frames are variants of `ControlFrame`. Direction: C→R means
client-to-relay, R→C relay-to-client.

### Register (C→R)

```rust
Register {
    version: u8,
    token:   Option<String>,
    kind:    TunnelKind,
}
```

First frame the client sends, on the control stream. `version` MUST
equal `PROTOCOL_VERSION` (1). `token` is required iff the relay was
started with `--auth-file`. `kind` is one of the `TunnelKind` variants
below.

### Registered (R→C)

```rust
Registered { public_url: String }
```

Sent by the relay after successful `Register`. `public_url` is the URL
end-users should hit to reach the client's local service.

### NewConn (R→C, on data streams)

```rust
NewConn { peer_addr: String }
```

Preamble written by the relay as the first bytes of every data stream.
`peer_addr` is the IP:port of the end-user as seen by the relay. Clients
MUST read exactly one frame, then treat the remainder of the stream as
opaque tunneled bytes.

### Ping (either direction, on control stream)

```rust
Ping
```

Keepalive. No reply is mandatory in v1. Receivers MUST decode and
discard.

### Error (either direction, terminal)

```rust
Error { code: u16, message: String }
```

Sender MUST close the connection (or at minimum the control stream)
after sending. Receivers treat as fatal.

## TunnelKind catalogue

```rust
TunnelKind::Http { subdomain: Option<String> }
TunnelKind::Tcp  { port: u16 }
```

- `Http { subdomain: Some(s) }` — client asks to register subdomain `s`.
  Relay replies with 409 if taken.
- `Http { subdomain: None }` — relay assigns a random subdomain.
- `Tcp { port: 0 }` — relay assigns a random high port.
- `Tcp { port: p }` — client requests port `p`; relay replies with 409
  if taken.

## Error codes

| Code | Meaning | Sender |
|---|---|---|
| 400 | Protocol error (bad version, malformed frame, oversized) | Either |
| 401 | Auth required (relay has `--auth-file`, client sent no token) | Relay |
| 403 | Invalid token | Relay |
| 409 | Subdomain or port already in use | Relay |
| 501 | Requested `TunnelKind` not yet implemented | Relay |

## Version negotiation

There is no negotiation in v1. If `Register.version` is not equal to
`PROTOCOL_VERSION`, relay MUST reply with `Error { code: 400, message:
"protocol version N unsupported" }` and close. Future versions may
introduce a `Hello`/`HelloAck` exchange; for now version is fail-closed.

## Security properties inherited from Seam

All Seamless frames ride on top of Seam streams, which give:

- **Confidentiality** via ChaCha20-Poly1305 packet encryption.
- **Integrity** via AEAD tag on each packet; any tampering breaks the
  decrypt.
- **Replay resistance** via Seam's 1024-bit per-connection replay window.
- **Post-quantum authentication** of the relay's long-term identity via
  the ML-KEM-768 half of the handshake.

Seamless adds no cryptography of its own. Auth tokens, when used, are plain
strings authenticated only by the fact that they traverse the already-
authenticated Seam channel.

## Wire examples

Client connects and registers subdomain `"demo"`:

```
# C→R, control stream, Register { version: 1, token: None, kind: Http { subdomain: Some("demo") } }
00 00 00 1b                                               # length = 27
00                                                        # variant 0 = Register
01                                                        # version = 1
00                                                        # token = None
00                                                        # variant 0 = Http
01 04 00 00 00 00 00 00 00 64 65 6d 6f                    # subdomain = Some("demo")
```

(Exact byte layout depends on bincode's default config. The above is a
sketch — for golden vectors, see `crates/seamless-common/tests/` once golden
tests exist.)

Relay reply on the same stream:

```
# R→C, Registered { public_url: "http://demo.localhost:8080" }
00 00 00 22                                               # length = 34
01                                                        # variant 1 = Registered
1a 00 00 00 00 00 00 00                                   # string length = 26 (u64 LE)
68 74 74 70 3a 2f 2f 64 65 6d 6f 2e 6c 6f 63 61
6c 68 6f 73 74 3a 38 30 38 30                             # "http://demo.localhost:8080"
```

Preamble on the first data stream opened by the relay:

```
# R→C, data stream N, NewConn { peer_addr: "1.2.3.4:50000" }
00 00 00 15                                               # length = 21
02                                                        # variant 2 = NewConn
0d 00 00 00 00 00 00 00                                   # string length = 13
31 2e 32 2e 33 2e 34 3a 35 30 30 30 30                    # "1.2.3.4:50000"
```
