use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use anyhow::{anyhow, Result};
use seamless_common::{write_frame, ControlFrame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::logs::{self, LogEntry};
use crate::store::unix_now;
use crate::AppState;

pub async fn run_http_ingress(addr: SocketAddr, state: AppState) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("http ingress listening on tcp://{addr}");
    loop {
        let (tcp, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = route_http(tcp, peer, state).await {
                warn!("http conn from {peer}: {e:#}");
            }
        });
    }
}

pub async fn run_https_ingress(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    state: AppState,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("https ingress listening on tcp://{addr}");
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls_stream) => {
                    if let Err(e) = route_http(tls_stream, peer, state).await {
                        warn!("https conn from {peer}: {e:#}");
                    }
                }
                Err(e) => {
                    warn!("tls handshake from {peer}: {e}");
                }
            }
        });
    }
}

async fn route_http<S>(mut stream: S, peer: SocketAddr, state: AppState) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut head = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];

    // Read until we have the full HTTP header block (ends with \r\n\r\n).
    // Cap at 64 KiB to guard against oversized headers.
    // Idle timeout: if no bytes arrive within 30 s, close without response.
    let read_result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok::<bool, std::io::Error>(false); // EOF before headers complete
            }
            head.extend_from_slice(&buf[..n]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(true);
            }
            if head.len() > 64 * 1024 {
                return Ok(false); // oversized
            }
        }
    })
    .await;

    match read_result {
        Err(_elapsed) => return Ok(()), // idle timeout — silently drop
        Ok(Err(e)) => return Err(e.into()),
        Ok(Ok(false)) if head.len() > 64 * 1024 => {
            let resp = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            if let Err(e) = stream.write_all(resp.as_bytes()).await {
                warn!("431 write failed for {peer}: {e}");
            }
            return Ok(());
        }
        Ok(Ok(false)) => return Ok(()), // EOF
        Ok(Ok(true)) => {} // full headers received
    }

    let host = match parse_host_header(&head) {
        Some(h) => h,
        None => {
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 25\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nmissing Host: header\n";
            if let Err(e) = stream.write_all(resp.as_bytes()).await {
                warn!("400 write failed for {peer}: {e}");
            }
            return Ok(());
        }
    };
    let (method, path) = parse_request_line(&head);

    // 1. Check proxy routes (static upstreams).
    let upstream_url = {
        let host_only = host.split(':').next().unwrap_or(&host).to_lowercase();
        let store = state.store.read().await;
        store
            .routes
            .iter()
            .find(|r| r.enabled && r.domain.to_lowercase() == host_only)
            .map(|r| r.upstream_url.clone())
    };

    if let Some(url) = upstream_url {
        let addr = match parse_upstream_addr(&url) {
            Ok(a) => a,
            Err(e) => {
                warn!("bad upstream URL '{url}': {e}");
                let body = format!("seamless: misconfigured upstream for '{host}'\n");
                let resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(resp.as_bytes()).await.ok();
                return Ok(());
            }
        };
        let upstream_result = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await;
        let mut upstream = match upstream_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!("upstream {addr} unreachable: {e}");
                logs::push(&state.log_buffer, LogEntry {
                    ts: unix_now(),
                    method,
                    path,
                    host,
                    routed_to: format!("proxy:{url}"),
                    status: 502,
                }).await;
                let body = format!("seamless: upstream '{addr}' unreachable\n");
                let resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(resp.as_bytes()).await.ok();
                return Ok(());
            }
            Err(_timeout) => {
                warn!("upstream {addr} connect timed out");
                logs::push(&state.log_buffer, LogEntry {
                    ts: unix_now(),
                    method,
                    path,
                    host,
                    routed_to: format!("proxy:{url}"),
                    status: 504,
                }).await;
                let body = format!("seamless: upstream '{addr}' timed out\n");
                let resp = format!(
                    "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(resp.as_bytes()).await.ok();
                return Ok(());
            }
        };
        upstream.write_all(&head).await?;
        logs::push(&state.log_buffer, LogEntry {
            ts: unix_now(),
            method,
            path,
            host,
            routed_to: format!("proxy:{url}"),
            status: 0, // upstream status comes back in the response stream; recorded as 0 = connected
        }).await;
        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
        return Ok(());
    }

    // 2. Check tunnel registry (Seam-backed subdomains).
    let sub = extract_subdomain(&host, &state.base_domain);
    if let Some(sub) = sub {
        let entry = {
            let t = state.tunnels.lock().await;
            t.get(&sub).cloned()
        };
        if let Some(entry) = entry {
            // If the tunnel is paused, return 503.
            if entry.paused.load(Ordering::Relaxed) {
                let body = format!("seamless: tunnel '{sub}' is paused\n");
                let resp = format!(
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                if let Err(e) = stream.write_all(resp.as_bytes()).await {
                    warn!("503 write failed for {peer}: {e}");
                }
                return Ok(());
            }

            state.metrics.inc_connections();
            logs::push(&state.log_buffer, LogEntry {
                ts: unix_now(),
                method,
                path,
                host,
                routed_to: format!("tunnel:{sub}"),
                status: 0,
            }).await;
            let mut apex = entry.mux.open_stream().await;
            write_frame(&mut apex, &ControlFrame::NewConn { peer_addr: peer.to_string() }).await?;
            if !head.is_empty() {
                let n = head.len() as u64;
                apex.write_all(&head).await?;
                entry.bytes_in.fetch_add(n, Ordering::Relaxed);
                state.metrics.inc_bytes_in(n);
            }
            let (n_in, n_out) = copy_bidirectional_counted(&mut stream, &mut apex).await;
            entry.bytes_in.fetch_add(n_in, Ordering::Relaxed);
            entry.bytes_out.fetch_add(n_out, Ordering::Relaxed);
            state.metrics.inc_bytes_in(n_in);
            state.metrics.inc_bytes_out(n_out);
            return Ok(());
        }
    }

    // 3. No route found — return 502.
    logs::push(&state.log_buffer, LogEntry {
        ts: unix_now(),
        method,
        path,
        host: host.clone(),
        routed_to: "none".to_string(),
        status: 502,
    }).await;
    let body = format!("seamless: no route for '{host}'\n");
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    if let Err(e) = stream.write_all(resp.as_bytes()).await {
        warn!("502 write failed for {peer}: {e}");
    }
    Ok(())
}

fn parse_request_line(bytes: &[u8]) -> (String, String) {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if let Some(line) = s.split("\r\n").next() {
            let mut parts = line.splitn(3, ' ');
            let method = parts.next().unwrap_or("?").to_string();
            let path = parts.next().unwrap_or("/").to_string();
            return (method, path);
        }
    }
    ("?".to_string(), "/".to_string())
}

fn parse_host_header(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    for line in s.split("\r\n") {
        if let Some(rest) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
            .or_else(|| line.strip_prefix("HOST:"))
        {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn extract_subdomain(host: &str, base: &str) -> Option<String> {
    let host = host.split(':').next().unwrap_or(host);
    let suffix = format!(".{base}");
    host.strip_suffix(&suffix).map(|s| s.to_string())
}

pub fn parse_upstream_addr(url: &str) -> Result<String> {
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    // Warn if URL contains a path — it will be silently dropped (TCP-level proxy)
    if stripped.contains('/') {
        warn!("upstream URL '{url}' contains a path — only host:port is used; path is ignored");
    }
    if host_port.is_empty() {
        return Err(anyhow!("empty host in upstream URL '{url}'"));
    }
    if host_port.contains(':') {
        Ok(host_port.to_string())
    } else {
        let default_port = if url.starts_with("https://") { 443 } else { 80 };
        Ok(format!("{host_port}:{default_port}"))
    }
}

/// Like `tokio::io::copy_bidirectional` but returns `(bytes_a_to_b, bytes_b_to_a)`.
async fn copy_bidirectional_counted<A, B>(a: &mut A, b: &mut B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(a, b).await {
        Ok((a2b, b2a)) => (a2b, b2a),
        Err(_) => (0, 0),
    }
}
