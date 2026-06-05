use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use seamless_common::{read_frame, write_frame, ControlFrame, TunnelKind, PROTOCOL_VERSION};
use seam_protocol::tunnel::{SeamMux, SeamStream};
use rand::Rng;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

use crate::metrics::Metrics;

// ── Public types ──────────────────────────────────────────────────────────────

/// Per-tunnel state shared between the tunnel task and the admin API.
pub struct TunnelEntry {
    pub mux: Arc<SeamMux>,
    pub subdomain: String,
    /// UTC Unix timestamp (seconds) when the tunnel was registered.
    pub connected_at: i64,
    /// IP address of the Seam client.
    pub client_ip: String,
    /// Bytes forwarded from the public internet into this tunnel.
    pub bytes_in: Arc<AtomicU64>,
    /// Bytes forwarded out of this tunnel to the public internet.
    pub bytes_out: Arc<AtomicU64>,
    /// When `true`, new incoming connections are refused with 503.
    pub paused: Arc<AtomicBool>,
    /// Allows the admin API to forcibly disconnect this tunnel.
    pub disconnect_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

pub type TunnelMap = Arc<Mutex<HashMap<String, Arc<TunnelEntry>>>>;
pub type TcpPortSet = Arc<Mutex<HashSet<u16>>>;

// ── Auth ──────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuthPolicy {
    allowed: Option<Arc<HashSet<String>>>,
}

impl AuthPolicy {
    pub fn open() -> Self {
        Self { allowed: None }
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading auth file {}", path.display()))?;
        let mut set = HashSet::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            set.insert(line.to_string());
        }
        if set.is_empty() {
            bail!("auth file {} had no tokens", path.display());
        }
        Ok(Self {
            allowed: Some(Arc::new(set)),
        })
    }

    pub fn check(&self, token: Option<&str>) -> std::result::Result<(), AuthError> {
        let Some(allowed) = &self.allowed else {
            return Ok(());
        };
        let Some(t) = token else {
            return Err(AuthError::Required);
        };
        let tbytes = t.as_bytes();
        let tlen = tbytes.len();
        let mut hit = 0u8;
        for candidate in allowed.iter() {
            let cbytes = candidate.as_bytes();
            // Constant-time: always call ct_eq even when lengths differ, using the
            // shorter slice so we never panic, then mask by the length comparison.
            // This avoids leaking whether any stored token has the same length.
            let len_match: u8 = if cbytes.len() == tlen { 1 } else { 0 };
            let cmp_len = cbytes.len().min(tlen);
            let eq: u8 = cbytes[..cmp_len].ct_eq(&tbytes[..cmp_len]).unwrap_u8();
            hit |= eq & len_match;
        }
        if hit == 1 {
            Ok(())
        } else {
            Err(AuthError::Invalid)
        }
    }
}

pub enum AuthError {
    Required,
    Invalid,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn handle_client(
    mux: Arc<SeamMux>,
    tunnels: TunnelMap,
    tcp_ports: TcpPortSet,
    base_domain: String,
    http_port: u16,
    auth: AuthPolicy,
    metrics: Metrics,
) -> Result<()> {
    let t0 = Instant::now();

    let mut control = mux
        .accept_stream()
        .await
        .ok_or_else(|| anyhow!("client dropped before opening control stream"))?;

    let frame = read_frame(&mut control)
        .await
        .context("reading register frame")?;

    let (kind, token) = match frame {
        ControlFrame::Register { version, kind, token } => {
            if version != PROTOCOL_VERSION {
                write_frame(
                    &mut control,
                    &ControlFrame::Error {
                        code: 400,
                        message: format!("protocol version {version} unsupported"),
                    },
                )
                .await
                .ok();
                return Err(anyhow!("version mismatch"));
            }
            (kind, token)
        }
        other => return Err(anyhow!("expected Register, got {other:?}")),
    };

    if let Err(e) = auth.check(token.as_deref()) {
        let (code, msg) = match e {
            AuthError::Required => (401, "auth required"),
            AuthError::Invalid => (403, "invalid token"),
        };
        write_frame(&mut control, &ControlFrame::Error { code, message: msg.into() })
            .await
            .ok();
        return Err(anyhow!("auth denied: {msg}"));
    }

    let handshake_ms = t0.elapsed().as_millis() as u64;
    metrics.record_handshake_ms(handshake_ms);

    match kind {
        TunnelKind::Http { subdomain } => {
            serve_http(mux, control, tunnels, base_domain, http_port, subdomain, metrics).await
        }
        TunnelKind::Tcp { port } => {
            serve_tcp(mux, control, tunnels, tcp_ports, base_domain, port, metrics).await
        }
    }
}

// ── HTTP tunnel ───────────────────────────────────────────────────────────────

async fn serve_http(
    mux: Arc<SeamMux>,
    mut control: SeamStream,
    tunnels: TunnelMap,
    base_domain: String,
    http_port: u16,
    subdomain: Option<String>,
    _metrics: Metrics,
) -> Result<()> {
    let sub = subdomain.unwrap_or_else(random_subdomain);
    let url = if http_port == 80 {
        format!("http://{sub}.{base_domain}")
    } else {
        format!("http://{sub}.{base_domain}:{http_port}")
    };

    let (disconnect_tx, disconnect_rx) = oneshot::channel::<()>();

    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let paused = Arc::new(AtomicBool::new(false));

    let entry = Arc::new(TunnelEntry {
        mux: mux.clone(),
        subdomain: sub.clone(),
        connected_at: crate::store::unix_now(),
        client_ip: String::new(), // Seam connections don't expose a meaningful client IP here
        bytes_in: bytes_in.clone(),
        bytes_out: bytes_out.clone(),
        paused: paused.clone(),
        disconnect_tx: Arc::new(Mutex::new(Some(disconnect_tx))),
    });

    {
        let mut t = tunnels.lock().await;
        if t.contains_key(&sub) {
            write_frame(
                &mut control,
                &ControlFrame::Error {
                    code: 409,
                    message: format!("subdomain '{sub}' already registered"),
                },
            )
            .await
            .ok();
            return Err(anyhow!("subdomain taken"));
        }
        t.insert(sub.clone(), entry);
    }

    write_frame(&mut control, &ControlFrame::Registered { public_url: url.clone() }).await?;
    info!("registered http tunnel: {url}");

    let mut ping_interval = tokio::time::interval(Duration::from_secs(25));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_interval.tick().await; // discard first immediate tick

    let mut drain = [0u8; 256];
    let mut disconnect_rx = disconnect_rx;
    loop {
        tokio::select! {
            _ = &mut disconnect_rx => {
                info!("admin forcibly disconnected http tunnel for subdomain {sub}");
                break;
            }
            _ = ping_interval.tick() => {
                if write_frame(&mut control, &ControlFrame::Ping).await.is_err() {
                    break;
                }
            }
            result = control.read(&mut drain) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }

    tunnels.lock().await.remove(&sub);
    info!("deregistered http tunnel for subdomain {sub}");
    Ok(())
}

// ── TCP tunnel ────────────────────────────────────────────────────────────────

async fn serve_tcp(
    mux: Arc<SeamMux>,
    mut control: SeamStream,
    tunnels: TunnelMap,
    tcp_ports: TcpPortSet,
    base_domain: String,
    requested_port: u16,
    _metrics: Metrics,
) -> Result<()> {
    let (listener, port) = match requested_port {
        0 => bind_random_port(&tcp_ports).await?,
        p => {
            let bound = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], p)))
                .await
                .map_err(|e| anyhow!("bind tcp :{p}: {e}"))?;
            tcp_ports.lock().await.insert(p);
            (bound, p)
        }
    };

    let url = format!("tcp://{base_domain}:{port}");
    write_frame(&mut control, &ControlFrame::Registered { public_url: url.clone() }).await?;
    info!("registered tcp tunnel: {url}");

    let (disconnect_tx, disconnect_rx) = oneshot::channel::<()>();
    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let tunnel_key = format!("tcp:{port}");

    let entry = Arc::new(TunnelEntry {
        mux: mux.clone(),
        subdomain: tunnel_key.clone(),
        connected_at: crate::store::unix_now(),
        client_ip: String::new(),
        bytes_in: bytes_in.clone(),
        bytes_out: bytes_out.clone(),
        paused: Arc::new(AtomicBool::new(false)),
        disconnect_tx: Arc::new(Mutex::new(Some(disconnect_tx))),
    });
    tunnels.lock().await.insert(tunnel_key.clone(), entry);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mux_for_listener = mux.clone();
    let listener_task = tokio::spawn(async move {
        run_tcp_listener(listener, mux_for_listener, shutdown_rx).await;
    });

    let mut ping_interval = tokio::time::interval(Duration::from_secs(25));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_interval.tick().await; // discard first immediate tick

    let mut drain = [0u8; 256];
    let mut disconnect_rx = disconnect_rx;
    loop {
        tokio::select! {
            _ = &mut disconnect_rx => {
                info!("admin forcibly disconnected tcp tunnel on port {port}");
                break;
            }
            _ = ping_interval.tick() => {
                if write_frame(&mut control, &ControlFrame::Ping).await.is_err() {
                    break;
                }
            }
            result = control.read(&mut drain) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }

    let _ = shutdown_tx.send(());
    let _ = listener_task.await;
    tcp_ports.lock().await.remove(&port);
    tunnels.lock().await.remove(&tunnel_key);
    info!("deregistered tcp tunnel on port {port}");
    Ok(())
}

async fn bind_random_port(in_use: &TcpPortSet) -> Result<(TcpListener, u16)> {
    for _ in 0..50 {
        let port: u16 = rand::thread_rng().gen_range(10_000..60_000);

        // Check our in-use set without holding the lock across the async bind.
        {
            if in_use.lock().await.contains(&port) {
                continue;
            }
        }

        match TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await {
            Ok(l) => {
                in_use.lock().await.insert(port);
                return Ok((l, port));
            }
            Err(_) => continue,
        }
    }
    bail!("could not find a free port in 10000..60000 after 50 tries")
}

async fn run_tcp_listener(
    listener: TcpListener,
    mux: Arc<SeamMux>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accept = listener.accept() => {
                let (tcp, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => { warn!("tcp accept: {e}"); continue; }
                };
                let mux = mux.clone();
                tokio::spawn(async move {
                    let stream = mux.open_stream().await;
                    if let Err(e) = forward_to_tunnel(tcp, stream, Vec::new(), peer).await {
                        warn!("tcp tunnel forward from {peer}: {e:#}");
                    }
                });
            }
        }
    }
}

pub async fn forward_to_tunnel(
    mut tcp: TcpStream,
    mut apex: SeamStream,
    already_read: Vec<u8>,
    peer: SocketAddr,
) -> Result<()> {
    write_frame(&mut apex, &ControlFrame::NewConn { peer_addr: peer.to_string() }).await?;
    if !already_read.is_empty() {
        apex.write_all(&already_read).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut apex).await;
    Ok(())
}

pub fn random_subdomain() -> String {
    const ADJECTIVES: &[&str] = &[
        "bold", "calm", "cold", "dark", "deep", "dim", "dry", "dull", "fair",
        "fast", "flat", "free", "full", "glad", "gray", "hard", "high", "keen",
        "kind", "late", "lean", "long", "loud", "low", "mild", "neat", "new",
        "odd", "open", "pale", "pure", "quick", "rare", "rich", "safe", "sharp",
        "slim", "slow", "soft", "still", "strong", "tall", "thin", "tidy",
        "true", "vast", "warm", "wild", "wise",
    ];
    const NOUNS: &[&str] = &[
        "arc", "ash", "bay", "beam", "bolt", "brook", "cave", "cliff", "cloud",
        "crest", "dale", "dawn", "dew", "drift", "dusk", "dust", "fern", "field",
        "flame", "flint", "fog", "ford", "frost", "gale", "gate", "glen", "grove",
        "haze", "hill", "lake", "leaf", "mist", "moon", "moss", "oak", "peak",
        "pine", "pond", "rain", "reef", "ridge", "river", "rock", "sand", "sea",
        "sky", "snow", "star", "stone", "stream", "tide", "vale", "wave", "wind",
    ];
    let mut rng = rand::thread_rng();
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let n: u16 = rng.gen_range(10..100);
    format!("{adj}-{noun}-{n}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(tokens: &[&str]) -> AuthPolicy {
        use std::collections::HashSet;
        AuthPolicy {
            allowed: Some(Arc::new(tokens.iter().map(|s| s.to_string()).collect::<HashSet<_>>())),
        }
    }

    #[test]
    fn auth_open_always_passes() {
        let p = AuthPolicy::open();
        assert!(p.check(None).is_ok());
        assert!(p.check(Some("anything")).is_ok());
    }

    #[test]
    fn auth_required_when_no_token_provided() {
        let p = policy_with(&["secret"]);
        assert!(matches!(p.check(None), Err(AuthError::Required)));
    }

    #[test]
    fn auth_valid_token_accepted() {
        let p = policy_with(&["mysecret"]);
        assert!(p.check(Some("mysecret")).is_ok());
    }

    #[test]
    fn auth_wrong_token_rejected() {
        let p = policy_with(&["mysecret"]);
        assert!(matches!(p.check(Some("wrong")), Err(AuthError::Invalid)));
        assert!(matches!(p.check(Some("mysecre")), Err(AuthError::Invalid))); // one char short
        assert!(matches!(p.check(Some("mysecrett")), Err(AuthError::Invalid))); // one char long
        assert!(matches!(p.check(Some("")), Err(AuthError::Invalid)));
    }

    #[test]
    fn auth_multi_token_any_accepted() {
        let p = policy_with(&["token-a", "token-b", "token-c"]);
        assert!(p.check(Some("token-a")).is_ok());
        assert!(p.check(Some("token-b")).is_ok());
        assert!(p.check(Some("token-c")).is_ok());
        assert!(matches!(p.check(Some("token-d")), Err(AuthError::Invalid)));
    }
}
