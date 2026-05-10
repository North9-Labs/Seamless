# Multi-stage build for seamless-relay.
#
# Build context convention: run from /root with both Seamless/ and Seam/
# sibling dirs present (Seam is a path-dependency):
#
#   docker build -f Seamless/Dockerfile -t seamless-relay .
#
FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Seam      /build/Seam
COPY Seamless  /build/Seamless

WORKDIR /build/Seamless
RUN cargo build --release --bin seamless-relay \
    && strip target/release/seamless-relay

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 65532 seamless \
    && useradd  --system --uid 65532 --gid 65532 --no-create-home \
                --home-dir /var/lib/seamless --shell /usr/sbin/nologin seamless \
    && install -d -m 0750 -o seamless -g seamless /var/lib/seamless

COPY --from=builder /build/Seamless/target/release/seamless-relay /usr/local/bin/seamless-relay

USER 65532:65532
EXPOSE 4443/udp 8080/tcp

ENTRYPOINT ["/usr/local/bin/seamless-relay"]
CMD ["--seam-addr", "0.0.0.0:4443", "--http-addr", "0.0.0.0:8080"]
