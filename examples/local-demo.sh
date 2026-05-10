#!/usr/bin/env bash
# Seamless local demo: build the workspace and drive the full tunnel flow
# end-to-end on loopback. Prints the tunneled HTTP response twice and
# tears down cleanly on exit/interrupt.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
    if [[ -x /build/north/prebuilts/rust/linux-x86/1.88.0/bin/cargo ]]; then
        export PATH=/build/north/prebuilts/rust/linux-x86/1.88.0/bin:$PATH
    else
        echo "cargo not on PATH — install rustup or set PATH manually" >&2
        exit 1
    fi
fi

APEX_ADDR=127.0.0.1:14443
HTTP_ADDR=127.0.0.1:18080
ORIGIN_PORT=13000
SUBDOMAIN=demo

RELAY_LOG=$(mktemp -t seamless-demo-relay.XXXXXX.log)
CLIENT_LOG=$(mktemp -t seamless-demo-client.XXXXXX.log)
ORIGIN_LOG=$(mktemp -t seamless-demo-origin.XXXXXX.log)
ORIGIN_DIR=$(mktemp -d -t seamless-demo-origin.XXXXXX)
echo "hello from seamless demo" > "$ORIGIN_DIR/index.html"

PIDS=()
cleanup() {
    local rc=$?
    if (( ${#PIDS[@]} )); then
        kill "${PIDS[@]}" 2>/dev/null || true
    fi
    rm -rf "$ORIGIN_DIR"
    exit $rc
}
trap cleanup EXIT INT TERM

echo "==> Building (this is cached after first run)"
cargo build --release --bin seamless-relay --bin seamless >/dev/null

echo "==> Starting origin on $ORIGIN_PORT"
python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 --directory "$ORIGIN_DIR" \
    > "$ORIGIN_LOG" 2>&1 &
PIDS+=($!)

echo "==> Starting relay on $APEX_ADDR / $HTTP_ADDR"
./target/release/seamless-relay --apex-addr "$APEX_ADDR" --http-addr "$HTTP_ADDR" \
    > "$RELAY_LOG" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 30); do
    X25519=$(grep "seam-pubkey-x25519" "$RELAY_LOG" 2>/dev/null | awk '{print $NF}' | head -1 || true)
    KEM=$(grep "seam-pubkey-kem " "$RELAY_LOG" 2>/dev/null | awk '{print $NF}' | head -1 || true)
    [[ -n "$X25519" && -n "$KEM" ]] && break
    sleep 0.1
done

if [[ -z "${X25519:-}" || -z "${KEM:-}" ]]; then
    echo "relay did not print pubkeys in time. log:" >&2
    cat "$RELAY_LOG" >&2
    exit 1
fi

echo "==> Starting client (subdomain $SUBDOMAIN → 127.0.0.1:$ORIGIN_PORT)"
./target/release/seamless --relay "$APEX_ADDR" --x25519 "$X25519" --kem "$KEM" \
    http "$ORIGIN_PORT" --subdomain "$SUBDOMAIN" \
    > "$CLIENT_LOG" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 50); do
    grep -q "public:" "$CLIENT_LOG" 2>/dev/null && break
    sleep 0.1
done
if ! grep -q "public:" "$CLIENT_LOG" 2>/dev/null; then
    echo "client did not register in time. logs:" >&2
    echo "-- relay --" >&2;  cat "$RELAY_LOG"  >&2
    echo "-- client --" >&2; cat "$CLIENT_LOG" >&2
    exit 1
fi

HTTP_PORT=${HTTP_ADDR##*:}
echo "==> Sending request 1 through the tunnel"
echo "[demo] response: $(curl -sS --fail -H "Host: ${SUBDOMAIN}.localhost:${HTTP_PORT}" "http://${HTTP_ADDR}/")"

echo "==> Sending request 2 through the tunnel"
echo "[demo] response: $(curl -sS --fail -H "Host: ${SUBDOMAIN}.localhost:${HTTP_PORT}" "http://${HTTP_ADDR}/")"

echo
echo "All good. Tunnel live at http://${SUBDOMAIN}.localhost:${HTTP_PORT}"
echo "Relay log: $RELAY_LOG"
echo "Client log: $CLIENT_LOG"
echo "(processes will be terminated on exit)"
sleep 2
