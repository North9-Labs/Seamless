# systemd

Run `seamless-relay` as a hardened system service.

## Install

From the project root, after `cargo build --release`:

```
sudo ./systemd/install.sh
sudo systemctl enable --now seamless-relay
```

## Files

- `seamless-relay.service` — unit file. Runs as dedicated `seamless` user with strict
  sandboxing (`ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`, etc.).
- `install.sh` — idempotent install script. Creates the `seamless` user, drops
  the binary in `/usr/local/bin`, installs the unit, seeds `/etc/seamless/relay.env`.

## Configuration

Extra CLI flags are read from `/etc/seamless/relay.env` as `SEAMLESS_RELAY_ARGS=...`.
Defaults in the unit bind `0.0.0.0:4443/udp` (Seam) and `0.0.0.0:8080/tcp`
(HTTP ingress).

## Logs

```
journalctl -u seamless-relay -f
```

The relay prints its X25519 and ML-KEM-768 public keys on startup — clients
need these to connect.
