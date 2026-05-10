use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::logs::{self, LogEntry};
use crate::store::unix_now;
use crate::tunnel::forward_to_tunnel;
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

async fn route_http(mut tcp: TcpStream, peer: SocketAddr, state: AppState) -> Result<()> {
    let mut head = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    let n = tcp.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    head.extend_from_slice(&buf[..n]);

    let host = parse_host_header(&head)
        .ok_or_else(|| anyhow!("no Host header in first {n} bytes"))?;
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
        let addr = parse_upstream_addr(&url)?;
        let mut upstream = TcpStream::connect(&addr)
            .await
            .map_err(|e| anyhow!("upstream {addr}: {e}"))?;
        upstream.write_all(&head).await?;
        logs::push(&state.log_buffer, LogEntry {
            ts: unix_now(),
            method,
            path,
            host,
            routed_to: format!("proxy:{url}"),
            status: 0,
        }).await;
        tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await?;
        return Ok(());
    }

    // 2. Check tunnel registry (Apex-backed subdomains).
    let sub = extract_subdomain(&host, &state.base_domain);
    if let Some(sub) = sub {
        let mux = {
            let t = state.tunnels.lock().await;
            t.get(&sub).cloned()
        };
        if let Some(mux) = mux {
            logs::push(&state.log_buffer, LogEntry {
                ts: unix_now(),
                method,
                path,
                host,
                routed_to: format!("tunnel:{sub}"),
                status: 0,
            }).await;
            let stream = mux.open_stream().await;
            return forward_to_tunnel(tcp, stream, head, peer).await;
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
    tcp.write_all(resp.as_bytes()).await.ok();
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
    if host_port.contains(':') {
        Ok(host_port.to_string())
    } else {
        let default_port = if url.starts_with("https://") { 443 } else { 80 };
        Ok(format!("{host_port}:{default_port}"))
    }
}
