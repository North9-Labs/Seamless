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
            if let Err(e) = route_http(tcp, peer, state, false).await {
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
                    if let Err(e) = route_http(tls_stream, peer, state, true).await {
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

async fn route_http<S>(mut stream: S, peer: SocketAddr, state: AppState, is_https: bool) -> Result<()>
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
            let resp = error_response("431 Request Header Fields Too Large", "", is_https);
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
            let resp = error_response("400 Bad Request", "missing Host: header\n", is_https);
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
                let resp = error_response("502 Bad Gateway", &body, is_https);
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
                let resp = error_response("502 Bad Gateway", &body, is_https);
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
                let resp = error_response("504 Gateway Timeout", &body, is_https);
                stream.write_all(resp.as_bytes()).await.ok();
                return Ok(());
            }
        };
        let fwd_head = inject_forwarding_headers(&head, &peer.ip().to_string(), is_https);
        upstream.write_all(&fwd_head).await?;
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
                let resp = error_response("503 Service Unavailable", &body, is_https);
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
                let fwd_head = inject_forwarding_headers(&head, &peer.ip().to_string(), is_https);
                let n = fwd_head.len() as u64;
                apex.write_all(&fwd_head).await?;
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
    let resp = error_response("502 Bad Gateway", &body, is_https);
    if let Err(e) = stream.write_all(resp.as_bytes()).await {
        warn!("502 write failed for {peer}: {e}");
    }
    Ok(())
}

/// Build a relay-generated HTTP error response.
/// When `is_https` is true, injects HSTS so browsers upgrade future requests.
fn error_response(status: &str, body: &str, is_https: bool) -> String {
    let hsts = if is_https {
        "Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n{hsts}Connection: close\r\n\r\n{body}",
        body.len()
    )
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
        // HTTP headers are case-insensitive (RFC 7230 §3.2).
        if let Some(colon) = line.find(':') {
            if line[..colon].eq_ignore_ascii_case("host") {
                return Some(line[colon + 1..].trim().to_string());
            }
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

/// Inject X-Forwarded-For, X-Real-IP, and X-Forwarded-Proto headers into raw HTTP head bytes.
/// Inserts after the request line so backend services can see the real client IP and protocol.
fn inject_forwarding_headers(head: &[u8], peer_ip: &str, is_https: bool) -> Vec<u8> {
    // Find the end of the first line (request line).
    let split_at = head.windows(2).position(|w| w == b"\r\n");
    let split_at = match split_at {
        Some(i) => i + 2, // include the \r\n
        None => return head.to_vec(), // malformed — pass through unchanged
    };
    let proto = if is_https { "https" } else { "http" };
    let injected = format!(
        "X-Forwarded-For: {peer_ip}\r\nX-Real-IP: {peer_ip}\r\nX-Forwarded-Proto: {proto}\r\n"
    );
    let mut out = Vec::with_capacity(head.len() + injected.len());
    out.extend_from_slice(&head[..split_at]);
    out.extend_from_slice(injected.as_bytes());
    out.extend_from_slice(&head[split_at..]);
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_exact() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_host_header(raw), Some("example.com".into()));
    }

    #[test]
    fn host_header_case_insensitive() {
        let cases = [
            b"GET / HTTP/1.1\r\nHOST: a.b.c\r\n\r\n" as &[u8],
            b"GET / HTTP/1.1\r\nhost: a.b.c\r\n\r\n",
            b"GET / HTTP/1.1\r\nHoSt: a.b.c\r\n\r\n",
        ];
        for raw in &cases {
            assert_eq!(parse_host_header(raw), Some("a.b.c".into()), "failed on {raw:?}");
        }
    }

    #[test]
    fn host_header_missing() {
        let raw = b"GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(parse_host_header(raw), None);
    }

    #[test]
    fn extract_subdomain_basic() {
        assert_eq!(extract_subdomain("foo.example.com", "example.com"), Some("foo".into()));
        assert_eq!(extract_subdomain("foo.example.com:8080", "example.com"), Some("foo".into()));
        assert_eq!(extract_subdomain("notexample.com", "example.com"), None);
        assert_eq!(extract_subdomain("example.com", "example.com"), None);
    }

    #[test]
    fn parse_upstream_addr_http() {
        assert_eq!(parse_upstream_addr("http://localhost:3000").unwrap(), "localhost:3000");
        assert_eq!(parse_upstream_addr("http://localhost").unwrap(), "localhost:80");
    }

    #[test]
    fn parse_upstream_addr_https() {
        assert_eq!(parse_upstream_addr("https://api.example.com").unwrap(), "api.example.com:443");
        assert_eq!(parse_upstream_addr("https://api.example.com:8443").unwrap(), "api.example.com:8443");
    }

    #[test]
    fn parse_upstream_addr_empty() {
        assert!(parse_upstream_addr("http://").is_err());
        assert!(parse_upstream_addr("").is_err());
    }

    #[test]
    fn inject_forwarding_headers_basic() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = inject_forwarding_headers(raw, "1.2.3.4", false);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"), "request line first");
        assert!(s.contains("X-Forwarded-For: 1.2.3.4\r\n"));
        assert!(s.contains("X-Real-IP: 1.2.3.4\r\n"));
        assert!(s.contains("X-Forwarded-Proto: http\r\n"));
        assert!(s.ends_with("Host: example.com\r\n\r\n"));
    }

    #[test]
    fn inject_forwarding_headers_https() {
        let raw = b"GET / HTTP/1.1\r\nHost: secure.example.com\r\n\r\n";
        let out = inject_forwarding_headers(raw, "10.0.0.1", true);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("X-Forwarded-Proto: https\r\n"));
    }

    #[test]
    fn error_response_http_no_hsts() {
        let r = error_response("502 Bad Gateway", "oops\n", false);
        assert!(!r.contains("Strict-Transport-Security"));
        assert!(r.contains("Content-Length: 5"));
    }

    #[test]
    fn error_response_https_has_hsts() {
        let r = error_response("503 Service Unavailable", "paused\n", true);
        assert!(r.contains("Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n"));
        assert!(r.contains("Content-Length: 7"));
    }
}
