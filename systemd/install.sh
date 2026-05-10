#!/usr/bin/env bash
# Install seamless-relay as a systemd service on the current host.
# Run from the project root after `cargo build --release`.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (sudo)" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/target/release/seamless-relay"

if [[ ! -x "$BIN" ]]; then
    echo "missing $BIN — run \`cargo build --release\` first" >&2
    exit 1
fi

if ! id -u seamless >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin seamless
fi

install -m 0755 "$BIN" /usr/local/bin/seamless-relay
install -d -m 0750 -o seamless -g seamless /var/lib/seamless /etc/seamless

if [[ ! -f /etc/seamless/relay.env ]]; then
    cat > /etc/seamless/relay.env <<'EOF'
# Extra flags appended to seamless-relay's command line.
# Defaults in the unit file already bind 0.0.0.0:4443 UDP and 0.0.0.0:8080 TCP.
#
# Examples:
#   SEAMLESS_RELAY_ARGS=--base-domain tunnel.example.com --auth-file /etc/seamless/tokens
#   SEAMLESS_RELAY_ARGS=--base-domain tunnel.example.com
SEAMLESS_RELAY_ARGS=
EOF
    chown seamless:seamless /etc/seamless/relay.env
    chmod 0640              /etc/seamless/relay.env
fi

install -m 0644 "$HERE/seamless-relay.service" /etc/systemd/system/seamless-relay.service
systemctl daemon-reload

cat <<EOF

installed.

Next:
  sudoedit /etc/seamless/relay.env        # optional — add base domain, auth file
  systemctl enable --now seamless-relay
  journalctl -u seamless-relay -f         # watch it boot, grab the pubkeys
EOF
