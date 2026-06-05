use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};
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

// ── Sliding-window rate limiter ───────────────────────────────────────────────

/// Sliding-window rate limiter: tracks connection timestamps per IP.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<tokio::sync::Mutex<HashMap<String, VecDeque<Instant>>>>,
    /// Max connections allowed in the window.
    max: u32,
    /// Window duration.
    window: Duration,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            max,
            window,
        }
    }

    /// Returns true if the IP is allowed, false if rate-limited.
    pub async fn check_and_record(&self, ip: &str) -> bool {
        if self.max == 0 {
            return true; // 0 = unlimited
        }
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let queue = map.entry(ip.to_string()).or_default();
        // Remove entries older than the window
        queue.retain(|&t| now.duration_since(t) < self.window);
        if queue.len() as u32 >= self.max {
            return false;
        }
        queue.push_back(now);
        true
    }
}

// ── Relay-level context passed into per-connection handlers ───────────────────

/// Immutable relay-level context that every tunnel handler needs.
pub struct ConnCtx {
    pub tunnels: TunnelMap,
    pub tcp_ports: TcpPortSet,
    pub base_domain: String,
    pub http_port: u16,
    pub https_port: Option<u16>,
    pub auth: AuthPolicy,
    pub metrics: Metrics,
    pub client_ip: String,
    /// Optional URL to POST webhook events to.
    pub webhook_url: Option<Arc<String>>,
    pub http_client: reqwest::Client,
    /// 0 = unlimited.
    pub max_tunnels_per_ip: u32,
    pub rate_limiter: RateLimiter,
    /// Global maximum simultaneous tunnels across all IPs (0 = unlimited).
    pub max_tunnels: u32,
}

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

/// Shared, hot-reloadable auth token set.
///
/// All clones of `AuthPolicy` share the same inner `RwLock<HashSet>`.
/// Calling `reload_from_file` atomically swaps the set so that every
/// in-flight and future connection sees the updated token list without
/// a process restart.  SIGHUP triggers the reload in `main`.
#[derive(Clone)]
pub struct AuthPolicy {
    /// `None` = open relay (no token required).
    allowed: Option<Arc<RwLock<HashSet<String>>>>,
}

impl AuthPolicy {
    pub fn open() -> Self {
        Self { allowed: None }
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let set = load_token_set(path)?;
        Ok(Self {
            allowed: Some(Arc::new(RwLock::new(set))),
        })
    }

    /// Re-read `path` and atomically replace the token set.
    /// Returns an error if the file is missing or empty — in that case the
    /// existing set remains unchanged so the relay stays protected.
    pub fn reload_from_file(&self, path: &Path) -> Result<()> {
        let Some(lock) = &self.allowed else {
            bail!("reload called on open auth policy — no file to reload");
        };
        let new_set = load_token_set(path)?;
        *lock.write().expect("auth RwLock poisoned") = new_set;
        Ok(())
    }

    pub fn check(&self, token: Option<&str>) -> std::result::Result<(), AuthError> {
        let Some(lock) = &self.allowed else {
            return Ok(());
        };
        let Some(t) = token else {
            return Err(AuthError::Required);
        };
        let allowed = lock.read().expect("auth RwLock poisoned");
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
        if hit == 1 { Ok(()) } else { Err(AuthError::Invalid) }
    }
}

fn load_token_set(path: &Path) -> Result<HashSet<String>> {
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
    Ok(set)
}

pub enum AuthError {
    Required,
    Invalid,
}

/// Webhook delivery context cloned into each tunnel handler.
#[derive(Clone)]
pub struct WebhookCtx {
    pub url: Option<Arc<String>>,
    pub client: reqwest::Client,
}

impl WebhookCtx {
    /// POST `body` to the configured webhook URL in a background task.
    /// Uses a 5-second timeout and retries once on transient failure.
    /// Failures are logged but never propagate to the caller.
    pub fn fire(&self, body: serde_json::Value) {
        let Some(url) = self.url.clone() else { return };
        let client = self.client.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::deliver(&client, &url, &body).await {
                warn!("webhook delivery failed (attempt 1/2): {e:#}");
                // Retry once after a short delay.
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Err(e2) = Self::deliver(&client, &url, &body).await {
                    warn!("webhook delivery failed (attempt 2/2): {e2:#}");
                }
            }
        });
    }

    async fn deliver(client: &reqwest::Client, url: &str, body: &serde_json::Value) -> Result<(), anyhow::Error> {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.post(url).json(body).send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("webhook POST timed out after 5s"))?
        .map_err(|e| anyhow::anyhow!("webhook POST error: {e}"))?;
        Ok(())
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn handle_client(mux: Arc<SeamMux>, ctx: ConnCtx) -> Result<()> {
    let ConnCtx {
        tunnels, tcp_ports, base_domain, http_port, https_port, auth, metrics, client_ip,
        webhook_url, http_client, max_tunnels_per_ip, rate_limiter, max_tunnels,
    } = ctx;
    let webhook = WebhookCtx { url: webhook_url, client: http_client };
    let t0 = Instant::now();

    // Wrap accept_stream + read_frame in a 30-second timeout to prevent
    // resource exhaustion from clients that connect but never register.
    let (mut control, frame) = tokio::time::timeout(
        Duration::from_secs(30),
        async {
            let mut control = mux
                .accept_stream()
                .await
                .ok_or_else(|| anyhow!("client dropped before opening control stream"))?;
            let frame = read_frame(&mut control)
                .await
                .context("reading register frame")?;
            Ok::<_, anyhow::Error>((control, frame))
        },
    )
    .await
    .map_err(|_| anyhow!("registration timeout from {client_ip}"))??;

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
        metrics.inc_auth_failures();
        tracing::warn!(
            event = "auth.failure",
            client_ip = %client_ip,
            reason = msg,
            "auth denied from {client_ip}: {msg}"
        );
        write_frame(&mut control, &ControlFrame::Error { code, message: msg.into() })
            .await
            .ok();
        return Err(anyhow!("auth denied: {msg}"));
    }

    let handshake_ms = t0.elapsed().as_millis() as u64;
    metrics.record_handshake_ms(handshake_ms);

    // Enforce per-IP connection rate limit.
    if !rate_limiter.check_and_record(&client_ip).await {
        metrics.inc_rate_limit_hits();
        tracing::warn!(
            event = "rate_limit.hit",
            client_ip = %client_ip,
            "rate limited connection from {client_ip}"
        );
        write_frame(&mut control, &ControlFrame::Error {
            code: 429,
            message: "too many connections from your IP — try again later".into(),
        }).await.ok();
        return Err(anyhow!("rate limited: {client_ip}"));
    }

    // Enforce per-IP tunnel limit.
    if max_tunnels_per_ip > 0 {
        let count = tunnels
            .lock()
            .await
            .values()
            .filter(|e| e.client_ip == client_ip)
            .count() as u32;
        if count >= max_tunnels_per_ip {
            metrics.inc_tunnel_per_ip_rejections();
            tracing::warn!(
                event = "tunnel.limit_per_ip",
                client_ip = %client_ip,
                limit = max_tunnels_per_ip,
                current = count,
                "per-IP tunnel limit reached for {client_ip}"
            );
            write_frame(
                &mut control,
                &ControlFrame::Error {
                    code: 429,
                    message: format!(
                        "tunnel limit reached for your IP ({max_tunnels_per_ip} max)"
                    ),
                },
            )
            .await
            .ok();
            return Err(anyhow!("tunnel limit exceeded for {client_ip}"));
        }
    }

    // Enforce global tunnel cap.
    if max_tunnels > 0 {
        let total = tunnels.lock().await.len() as u32;
        if total >= max_tunnels {
            metrics.inc_tunnel_cap_rejections();
            tracing::warn!(
                event = "tunnel.cap_reached",
                client_ip = %client_ip,
                limit = max_tunnels,
                current = total,
                "global tunnel cap reached ({max_tunnels}), rejecting {client_ip}"
            );
            write_frame(
                &mut control,
                &ControlFrame::Error {
                    code: 503,
                    message: format!("relay at capacity ({max_tunnels} tunnels) — try again later"),
                },
            )
            .await
            .ok();
            return Err(anyhow!("global tunnel cap reached for {client_ip}"));
        }
    }

    match kind {
        TunnelKind::Http { subdomain } => {
            serve_http(mux, control, tunnels, &base_domain, http_port, https_port, subdomain, metrics, &client_ip, webhook).await
        }
        TunnelKind::Tcp { port } => {
            serve_tcp(mux, control, tunnels, tcp_ports, &base_domain, port, metrics, &client_ip, webhook).await
        }
    }
}

// ── Subdomain validation ──────────────────────────────────────────────────────

fn validate_subdomain(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 63 {
        bail!("subdomain must be 1–63 characters");
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("subdomain may only contain [a-z0-9-]");
    }
    if s.starts_with('-') || s.ends_with('-') {
        bail!("subdomain must not start or end with '-'");
    }
    Ok(())
}

// ── HTTP tunnel ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn serve_http(
    mux: Arc<SeamMux>,
    mut control: SeamStream,
    tunnels: TunnelMap,
    base_domain: &str,
    http_port: u16,
    https_port: Option<u16>,
    subdomain: Option<String>,
    metrics: Metrics,
    client_ip: &str,
    webhook: WebhookCtx,
) -> Result<()> {
    // Validate client-requested subdomains before falling back to random.
    if let Some(ref requested) = subdomain {
        if let Err(e) = validate_subdomain(requested) {
            metrics.inc_subdomain_invalid();
            tracing::warn!(
                event = "subdomain.invalid",
                client_ip = %client_ip,
                subdomain = %requested,
                reason = %e,
                "invalid subdomain '{requested}' from {client_ip}: {e}"
            );
            write_frame(&mut control, &ControlFrame::Error { code: 400, message: e.to_string() }).await.ok();
            return Err(anyhow!("invalid subdomain '{requested}': {e}"));
        }
    }
    let sub = subdomain.unwrap_or_else(random_subdomain);
    let url = if let Some(port) = https_port {
        if port == 443 {
            format!("https://{sub}.{base_domain}")
        } else {
            format!("https://{sub}.{base_domain}:{port}")
        }
    } else if http_port == 80 {
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
        client_ip: client_ip.to_string(),
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
    let connected_at = crate::store::unix_now();
    info!(
        event = "tunnel.open",
        kind = "http",
        subdomain = %sub,
        url = %url,
        client_ip = %client_ip,
        connected_at = connected_at,
        "http tunnel opened: {url} from {client_ip}"
    );
    webhook.fire(serde_json::json!({
        "event": "tunnel.connect",
        "kind": "http",
        "subdomain": sub,
        "url": url,
        "client_ip": client_ip,
    }));

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
    let duration_secs = crate::store::unix_now() - connected_at;
    info!(
        event = "tunnel.close",
        kind = "http",
        subdomain = %sub,
        url = %url,
        client_ip = %client_ip,
        duration_secs = duration_secs,
        "http tunnel closed: {sub} (duration {duration_secs}s)"
    );
    webhook.fire(serde_json::json!({
        "event": "tunnel.disconnect",
        "kind": "http",
        "subdomain": sub,
        "url": url,
        "client_ip": client_ip,
        "duration_secs": duration_secs,
    }));
    Ok(())
}

// ── TCP tunnel ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn serve_tcp(
    mux: Arc<SeamMux>,
    mut control: SeamStream,
    tunnels: TunnelMap,
    tcp_ports: TcpPortSet,
    base_domain: &str,
    requested_port: u16,
    metrics: Metrics,
    client_ip: &str,
    webhook: WebhookCtx,
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
    let connected_at = crate::store::unix_now();
    info!(
        event = "tunnel.open",
        kind = "tcp",
        port = port,
        url = %url,
        client_ip = %client_ip,
        connected_at = connected_at,
        "tcp tunnel opened: {url} from {client_ip}"
    );
    webhook.fire(serde_json::json!({
        "event": "tunnel.connect",
        "kind": "tcp",
        "port": port,
        "url": url,
        "client_ip": client_ip,
    }));

    let (disconnect_tx, disconnect_rx) = oneshot::channel::<()>();
    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let tunnel_key = format!("tcp:{port}");

    let entry = Arc::new(TunnelEntry {
        mux: mux.clone(),
        subdomain: tunnel_key.clone(),
        connected_at: crate::store::unix_now(),
        client_ip: client_ip.to_string(),
        bytes_in: bytes_in.clone(),
        bytes_out: bytes_out.clone(),
        paused: Arc::new(AtomicBool::new(false)),
        disconnect_tx: Arc::new(Mutex::new(Some(disconnect_tx))),
    });
    tunnels.lock().await.insert(tunnel_key.clone(), entry);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mux_for_listener = mux.clone();
    let bi2 = bytes_in.clone();
    let bo2 = bytes_out.clone();
    let met2 = metrics.clone();
    let listener_task = tokio::spawn(async move {
        run_tcp_listener(listener, mux_for_listener, shutdown_rx, bi2, bo2, met2).await;
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
    let duration_secs = crate::store::unix_now() - connected_at;
    info!(
        event = "tunnel.close",
        kind = "tcp",
        port = port,
        url = %url,
        client_ip = %client_ip,
        duration_secs = duration_secs,
        "tcp tunnel closed: port {port} (duration {duration_secs}s)"
    );
    webhook.fire(serde_json::json!({
        "event": "tunnel.disconnect",
        "kind": "tcp",
        "port": port,
        "url": url,
        "client_ip": client_ip,
        "duration_secs": duration_secs,
    }));
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
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    metrics: Metrics,
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
                let bi = bytes_in.clone();
                let bo = bytes_out.clone();
                let met = metrics.clone();
                tokio::spawn(async move {
                    let stream = mux.open_stream().await;
                    if let Err(e) = forward_to_tunnel(tcp, stream, Vec::new(), peer, bi, bo, met).await {
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
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    metrics: Metrics,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    write_frame(&mut apex, &ControlFrame::NewConn { peer_addr: peer.to_string() }).await?;
    if !already_read.is_empty() {
        let n = already_read.len() as u64;
        apex.write_all(&already_read).await?;
        bytes_in.fetch_add(n, Ordering::Relaxed);
        metrics.inc_bytes_in(n);
    }
    if let Ok((n_in, n_out)) = tokio::io::copy_bidirectional(&mut tcp, &mut apex).await {
        bytes_in.fetch_add(n_in, Ordering::Relaxed);
        bytes_out.fetch_add(n_out, Ordering::Relaxed);
        metrics.inc_bytes_in(n_in);
        metrics.inc_bytes_out(n_out);
    }
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
            allowed: Some(Arc::new(std::sync::RwLock::new(tokens.iter().map(|s| s.to_string()).collect::<HashSet<_>>()))),
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

    #[test]
    fn validate_subdomain_valid() {
        assert!(validate_subdomain("abc").is_ok());
        assert!(validate_subdomain("abc-def").is_ok());
        assert!(validate_subdomain("abc123").is_ok());
        assert!(validate_subdomain("a").is_ok());
        assert!(validate_subdomain(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn validate_subdomain_invalid() {
        assert!(validate_subdomain("").is_err());               // empty
        assert!(validate_subdomain("-abc").is_err());           // leading hyphen
        assert!(validate_subdomain("abc-").is_err());           // trailing hyphen
        assert!(validate_subdomain("abc.def").is_err());        // dot not allowed
        assert!(validate_subdomain("abc def").is_err());        // space not allowed
        assert!(validate_subdomain("abc_def").is_err());        // underscore not allowed
        assert!(validate_subdomain(&"a".repeat(64)).is_err());  // too long
    }

    #[tokio::test]
    async fn rate_limiter_allows_within_limit() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.check_and_record("1.2.3.4").await);
        assert!(rl.check_and_record("1.2.3.4").await);
        assert!(rl.check_and_record("1.2.3.4").await);
        // 4th should be denied
        assert!(!rl.check_and_record("1.2.3.4").await);
    }

    #[tokio::test]
    async fn rate_limiter_unlimited_when_zero() {
        let rl = RateLimiter::new(0, Duration::from_secs(60));
        for _ in 0..100 {
            assert!(rl.check_and_record("1.2.3.4").await);
        }
    }

    #[tokio::test]
    async fn rate_limiter_separate_ips_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        assert!(rl.check_and_record("1.1.1.1").await);
        assert!(!rl.check_and_record("1.1.1.1").await); // second from same IP denied
        assert!(rl.check_and_record("2.2.2.2").await);  // different IP still allowed
    }
}
