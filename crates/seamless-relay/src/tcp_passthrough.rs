// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! Raw TCP passthrough — forward any TCP port to a backend host:port without
//! HTTP parsing. Useful for databases (Postgres, Redis, MySQL), game servers,
//! SSH, custom protocols, etc.
//!
//! Each passthrough listener is independent and runs in its own Tokio task.
//! Connections are subject to the IP deny list and per-IP rate limiting.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::audit::AuditLog;
use crate::denylist::IpDenyList;
use crate::geoip::GeoipFilter;
use crate::metrics::Metrics;
use crate::tunnel::RateLimiter;

/// Configuration for a single TCP passthrough listener.
#[derive(Debug, Clone)]
pub struct TcpPassthroughConfig {
    /// Local port to listen on.
    pub listen_port: u16,
    /// Backend hostname or IP to forward connections to.
    pub backend_host: String,
    /// Backend port to forward connections to.
    pub backend_port: u16,
}

impl TcpPassthroughConfig {
    /// Parse a `port:host:backend_port` string.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            anyhow::bail!(
                "invalid --tcp-passthrough format '{}': expected <listen_port>:<backend_host>:<backend_port>",
                s
            );
        }
        let listen_port: u16 = parts[0].parse().map_err(|_| {
            anyhow::anyhow!("invalid listen port '{}' in --tcp-passthrough", parts[0])
        })?;
        let backend_host = parts[1].to_string();
        let backend_port: u16 = parts[2].parse().map_err(|_| {
            anyhow::anyhow!("invalid backend port '{}' in --tcp-passthrough", parts[2])
        })?;
        Ok(Self {
            listen_port,
            backend_host,
            backend_port,
        })
    }
}

/// Shared gauge tracking currently active passthrough connections.
pub static TCP_PASSTHROUGH_CONNECTIONS_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Spawn a TCP passthrough listener for the given config.
///
/// Runs until the process exits. Each accepted connection is forwarded
/// bidirectionally to the configured backend using `copy_bidirectional`.
pub async fn run_tcp_passthrough(
    cfg: TcpPassthroughConfig,
    ip_denylist: IpDenyList,
    rate_limiter: RateLimiter,
    geoip: Arc<GeoipFilter>,
    metrics: Metrics,
    audit_log: AuditLog,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", cfg.listen_port);
    let listener = TcpListener::bind(&addr).await?;
    info!(
        "tcp-passthrough: listening on tcp://{} → {}:{}",
        addr, cfg.backend_host, cfg.backend_port
    );

    loop {
        let (client_tcp, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "tcp-passthrough: accept error on port {}: {e}",
                    cfg.listen_port
                );
                continue;
            }
        };

        let peer_ip: IpAddr = peer_addr.ip();

        // ── IP deny list check ────────────────────────────────────────────────
        if ip_denylist.is_denied(peer_ip) {
            warn!(
                event = "tcp_passthrough.denied",
                peer = %peer_addr,
                listen_port = cfg.listen_port,
                "tcp-passthrough: connection from {peer_addr} denied by IP denylist"
            );
            crate::audit_event!(audit_log, "tcp_passthrough.denied",
                "peer"         => peer_addr.to_string(),
                "listen_port"  => cfg.listen_port,
                "reason"       => "ip_denylist"
            );
            continue;
        }

        // ── Geo-IP block check ────────────────────────────────────────────────
        if let Some(cc) = geoip.country_code(peer_ip) {
            if geoip.is_blocked(peer_ip) {
                warn!(
                    event = "tcp_passthrough.geo_blocked",
                    peer = %peer_addr,
                    listen_port = cfg.listen_port,
                    country = %cc,
                    "tcp-passthrough: connection from {peer_addr} blocked (country {cc})"
                );
                crate::audit_event!(audit_log, "tcp_passthrough.geo_blocked",
                    "peer"         => peer_addr.to_string(),
                    "listen_port"  => cfg.listen_port,
                    "country"      => &cc
                );
                continue;
            }
        } else if geoip.is_blocked(peer_ip) {
            // is_blocked returns true when the reader is Some but lookup fails
            // and the country is in the blocked list — shouldn't happen in normal
            // operation, but handle defensively.
            warn!(
                event = "tcp_passthrough.geo_blocked",
                peer = %peer_addr,
                listen_port = cfg.listen_port,
                "tcp-passthrough: connection from {peer_addr} geo-blocked (unknown country)"
            );
            crate::audit_event!(audit_log, "tcp_passthrough.geo_blocked",
                "peer"        => peer_addr.to_string(),
                "listen_port" => cfg.listen_port,
                "country"     => "unknown"
            );
            continue;
        }

        // ── Rate limit check ──────────────────────────────────────────────────
        if !rate_limiter.check_and_record(&peer_ip.to_string()).await {
            warn!(
                event = "tcp_passthrough.rate_limited",
                peer = %peer_addr,
                listen_port = cfg.listen_port,
                "tcp-passthrough: connection from {peer_addr} rate-limited"
            );
            crate::audit_event!(audit_log, "tcp_passthrough.rate_limited",
                "peer"         => peer_addr.to_string(),
                "listen_port"  => cfg.listen_port
            );
            metrics.inc_rate_limit_hits();
            continue;
        }

        // Spawn a task for this connection.
        let backend_addr = format!("{}:{}", cfg.backend_host, cfg.backend_port);
        let audit = audit_log.clone();
        let listen_port = cfg.listen_port;

        tokio::spawn(async move {
            TCP_PASSTHROUGH_CONNECTIONS_ACTIVE.fetch_add(1, Ordering::Relaxed);
            crate::audit_event!(audit, "tcp_passthrough.connect",
                "peer"         => peer_addr.to_string(),
                "listen_port"  => listen_port,
                "backend"      => &backend_addr
            );
            info!(
                event = "tcp_passthrough.connect",
                peer = %peer_addr,
                backend = %backend_addr,
                "tcp-passthrough: connection from {peer_addr} → {backend_addr}"
            );

            let (bytes_in, bytes_out) = forward(client_tcp, &backend_addr).await;

            TCP_PASSTHROUGH_CONNECTIONS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
            crate::audit_event!(audit, "tcp_passthrough.disconnect",
                "peer"         => peer_addr.to_string(),
                "listen_port"  => listen_port,
                "backend"      => &backend_addr,
                "bytes_in"     => bytes_in,
                "bytes_out"    => bytes_out
            );
            info!(
                event = "tcp_passthrough.disconnect",
                peer = %peer_addr,
                backend = %backend_addr,
                bytes_in = bytes_in,
                bytes_out = bytes_out,
                "tcp-passthrough: {peer_addr} disconnected (in={bytes_in}B out={bytes_out}B)"
            );
        });
    }
}

/// Connect to `backend_addr` and splice `client` bidirectionally.
/// Returns `(client_to_backend_bytes, backend_to_client_bytes)`.
async fn forward(client: TcpStream, backend_addr: &str) -> (u64, u64) {
    let backend = match TcpStream::connect(backend_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("tcp-passthrough: could not connect to backend {backend_addr}: {e}");
            return (0, 0);
        }
    };

    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut backend_r, mut backend_w) = tokio::io::split(backend);

    // Run both copy directions concurrently; cancel the other when either finishes.
    let client_to_backend = tokio::io::copy(&mut client_r, &mut backend_w);
    let backend_to_client = tokio::io::copy(&mut backend_r, &mut client_w);

    let (bytes_in, bytes_out) = tokio::join!(client_to_backend, backend_to_client);
    (bytes_in.unwrap_or(0), bytes_out.unwrap_or(0))
}
