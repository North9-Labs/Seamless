use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use seam_protocol::api::Server;
use seam_protocol::handshake::{IdentityKeypair, pk_to_bytes};
use seam_protocol::tunnel::SeamMux;
use clap::Parser;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

mod admin;
mod cloudflare;
mod ingress;
mod logs;
mod metrics;
mod store;
mod tls;
mod tunnel;

use logs::LogBuffer;
use metrics::Metrics;
use store::SharedStore;
use tunnel::{AuthPolicy, RateLimiter, ReservedSubdomains, SubdomainPrefix, TcpPortSet, TunnelMap};

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub store_path: Arc<PathBuf>,
    pub tunnels: TunnelMap,
    pub tcp_ports: TcpPortSet,
    pub base_domain: Arc<String>,
    pub relay_pubkeys: Arc<RelayPubkeys>,
    pub seam_addr: String,
    pub http_port: u16,
    /// Set when the relay is running with TLS — used to build https:// tunnel URLs.
    pub https_port: Option<u16>,
    pub auth: AuthPolicy,
    pub http_client: reqwest::Client,
    pub log_buffer: LogBuffer,
    pub metrics: Metrics,
    pub start_time: Arc<Instant>,
    /// Optional Bearer token protecting admin-only endpoints.
    pub admin_token: Arc<Option<String>>,
    /// The cipher suite this relay was started with.
    pub cipher: Arc<String>,
    /// Path to the auth token file, if any. Stored so SIGHUP can reload it.
    pub auth_file: Arc<Option<PathBuf>>,
    /// Optional webhook URL to POST tunnel events to.
    pub webhook_url: Arc<Option<String>>,
    /// Max simultaneous tunnels per client IP (0 = unlimited).
    pub max_tunnels_per_ip: u32,
    /// Global max simultaneous tunnels across all IPs (0 = unlimited).
    pub max_tunnels: u32,
    /// Per-IP new-connection rate limiter.
    pub rate_limiter: RateLimiter,
    /// Allowed CIDRs for admin UI access. Empty = allow all.
    pub admin_cidrs: Arc<Vec<(u32, u32)>>,
    /// Path to the config file that was loaded at startup, if any.
    pub config_file: Arc<Option<PathBuf>>,
    /// Subdomains blocked from registration (e.g., "admin", "www", "api").
    pub reserved_subdomains: ReservedSubdomains,
    /// Optional prefix all client-requested subdomains must start with.
    pub subdomain_prefix: SubdomainPrefix,
    /// Number of random alphanumeric chars for auto-assigned subdomains (default 8, min 6).
    pub subdomain_length: usize,
    /// Max tunnel age in seconds (0 = unlimited). Background task expires old tunnels.
    pub tunnel_max_age: u64,
}

pub struct RelayPubkeys {
    pub x25519: String,
    pub kem: String,
}

// ── Config file ──────────────────────────────────────────────────────────────

/// Optional TOML config file. All fields map 1-to-1 with CLI flags.
/// CLI flags always override config file values.
/// Searched in order:
///   1. Path from `--config` CLI flag
///   2. ~/.config/seamless/relay.toml
///   3. /etc/seamless/relay.toml
#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    seam_addr: Option<String>,
    http_addr: Option<String>,
    admin_addr: Option<String>,
    base_domain: Option<String>,
    auth_file: Option<PathBuf>,
    store: Option<String>,
    log_level: Option<String>,
    log_format: Option<String>,
    admin_token: Option<String>,
    https_addr: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_self_signed: Option<bool>,
    max_tunnels_per_ip: Option<u32>,
    webhook_url: Option<String>,
    cipher: Option<String>,
    rate_limit: Option<u32>,
    max_tunnels: Option<u32>,
    admin_allow_cidr: Option<String>,
    admin_tls_cert: Option<String>,
    admin_tls_key: Option<String>,
    admin_client_ca: Option<String>,
    reserved_subdomains: Option<String>,
    subdomain_prefix: Option<String>,
    subdomain_length: Option<usize>,
    tunnel_max_age: Option<u64>,
}

/// Find and load the TOML config file, returning the loaded config and the
/// path that was actually used (if any).
/// Returns an empty/default config if no file is found.
fn load_file_config(explicit_path: Option<&PathBuf>) -> (FileConfig, Option<PathBuf>) {
    // 1. Explicit --config flag takes priority.
    if let Some(p) = explicit_path {
        match std::fs::read_to_string(p) {
            Ok(text) => match toml::from_str::<FileConfig>(&text) {
                Ok(cfg) => {
                    eprintln!("seamless: loaded config from {}", p.display());
                    return (cfg, Some(p.clone()));
                }
                Err(e) => {
                    eprintln!("seamless: error parsing config {}: {e}", p.display());
                    return (FileConfig::default(), None);
                }
            },
            Err(e) => {
                eprintln!("seamless: cannot read config {}: {e}", p.display());
                return (FileConfig::default(), None);
            }
        }
    }

    // 2. ~/.config/seamless/relay.toml
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join(".config/seamless/relay.toml");
        if p.exists() {
            if let Ok(text) = std::fs::read_to_string(&p) {
                if let Ok(cfg) = toml::from_str::<FileConfig>(&text) {
                    eprintln!("seamless: loaded config from {}", p.display());
                    return (cfg, Some(p));
                }
            }
        }
    }

    // 3. /etc/seamless/relay.toml
    let etc = PathBuf::from("/etc/seamless/relay.toml");
    if etc.exists() {
        if let Ok(text) = std::fs::read_to_string(&etc) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&text) {
                eprintln!("seamless: loaded config from {}", etc.display());
                return (cfg, Some(etc));
            }
        }
    }

    (FileConfig::default(), None)
}

#[derive(Parser, Debug)]
#[command(name = "seamless-relay", about = "Seamless — PQ reverse tunnel relay")]
struct Args {
    /// Path to a TOML config file. CLI flags override config file values.
    /// If not set, looks for ~/.config/seamless/relay.toml then /etc/seamless/relay.toml.
    #[arg(long, env = "SEAMLESS_CONFIG")]
    config: Option<PathBuf>,

    /// UDP address for Seam connections from tunnel clients.
    #[arg(long, default_value = "0.0.0.0:4443")]
    seam_addr: SocketAddr,

    /// TCP address for public HTTP ingress.
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_addr: SocketAddr,

    /// TCP address for the admin UI and REST API.
    #[arg(long, default_value = "0.0.0.0:8088")]
    admin_addr: SocketAddr,

    /// Base domain used to build public tunnel URLs.
    #[arg(long, default_value = "localhost")]
    base_domain: String,

    /// Path to a file of allowed auth tokens (one per line).
    #[arg(long)]
    auth_file: Option<PathBuf>,

    /// Path to the JSON store file (proxy routes + relay identity).
    #[arg(long, default_value = "seamless-relay.json")]
    store: String,

    /// Log level: error, warn, info, debug, trace (overrides RUST_LOG).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Bearer token required for admin-only endpoints (DELETE/pause/resume tunnels).
    /// If not set, admin management endpoints are open to anyone who can reach the admin port.
    #[arg(long, env = "SEAMLESS_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// TCP address for public HTTPS ingress (requires --tls-cert/--tls-key or --tls-self-signed).
    #[arg(long)]
    https_addr: Option<SocketAddr>,

    /// Path to TLS certificate PEM file for HTTPS.
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key PEM file for HTTPS.
    #[arg(long)]
    tls_key: Option<String>,

    /// Generate and use a self-signed TLS certificate for HTTPS.
    #[arg(long, default_value_t = false)]
    tls_self_signed: bool,

    /// Maximum simultaneous tunnels per client IP (0 = unlimited).
    #[arg(long, default_value_t = 10, env = "SEAMLESS_MAX_TUNNELS_PER_IP")]
    max_tunnels_per_ip: u32,

    /// Optional URL to POST webhook events to (tunnel.connect / tunnel.disconnect).
    /// If set, the relay will POST JSON to this URL when tunnels register or disconnect.
    #[arg(long, env = "SEAMLESS_WEBHOOK_URL")]
    webhook_url: Option<String>,

    /// AEAD cipher suite preference for tunnel connections.
    /// "chacha20poly1305" (default) or "aes256gcm" (CNSA 2.0).
    /// AES-256-GCM is negotiated only when both the relay and the connecting
    /// client advertise it; mismatching sides fall back to ChaCha20-Poly1305.
    #[arg(long, default_value = "chacha20poly1305",
          value_parser = ["chacha20poly1305", "aes256gcm"],
          env = "SEAMLESS_CIPHER")]
    cipher: String,

    /// Max new tunnel registrations per minute per client IP (0 = unlimited).
    #[arg(long, default_value_t = 10, env = "SEAMLESS_RATE_LIMIT")]
    rate_limit: u32,

    /// Global maximum simultaneous tunnels across all clients (0 = unlimited).
    /// Reaching this cap causes new tunnel attempts to be rejected with 503.
    #[arg(long, default_value_t = 1000, env = "SEAMLESS_MAX_TUNNELS")]
    max_tunnels: u32,

    /// Log output format: "text" (human-readable, default) or "json" (structured, for SIEM/log aggregators).
    #[arg(long, default_value = "text", value_parser = ["text", "json"], env = "SEAMLESS_LOG_FORMAT")]
    log_format: String,

    /// Restrict admin UI access to these CIDRs (comma-separated, e.g. 10.0.0.0/8,192.168.1.0/24).
    /// If not set, all IPs are allowed. Can be repeated.
    #[arg(long, env = "SEAMLESS_ADMIN_ALLOW_CIDR")]
    admin_allow_cidr: Option<String>,

    /// Path to TLS certificate PEM for the admin port.
    /// When set with --admin-tls-key, the admin API is served over TLS 1.3.
    #[arg(long, env = "SEAMLESS_ADMIN_TLS_CERT")]
    admin_tls_cert: Option<String>,

    /// Path to TLS private key PEM for the admin port.
    #[arg(long, env = "SEAMLESS_ADMIN_TLS_KEY")]
    admin_tls_key: Option<String>,

    /// Path to a CA certificate PEM used to verify admin client certificates (mutual TLS).
    /// Requires --admin-tls-cert and --admin-tls-key. Only clients presenting a certificate
    /// signed by this CA will be allowed to connect — recommended for government deployments.
    #[arg(long, env = "SEAMLESS_ADMIN_CLIENT_CA")]
    admin_client_ca: Option<String>,

    /// Comma-separated list of subdomains that clients are forbidden from registering.
    /// Example: "admin,www,api,mail,vpn,git,internal"
    /// Attempts to claim a reserved subdomain return HTTP 403.
    #[arg(long, env = "SEAMLESS_RESERVED_SUBDOMAINS")]
    reserved_subdomains: Option<String>,

    /// Required prefix for all client-requested subdomains (e.g. "dev-" or "user-").
    /// Clients that request a subdomain not starting with this prefix receive HTTP 403.
    /// Does not affect auto-assigned (random) subdomains.
    /// Useful for multi-team deployments where naming conventions are enforced.
    #[arg(long, env = "SEAMLESS_SUBDOMAIN_PREFIX")]
    subdomain_prefix: Option<String>,

    /// Length (in characters) of randomly-assigned subdomains when the client does not
    /// request a specific one. Default 8, minimum 6. Longer = harder to guess/enumerate.
    #[arg(long, default_value_t = 8, env = "SEAMLESS_SUBDOMAIN_LENGTH")]
    subdomain_length: usize,

    /// Maximum tunnel lifetime in seconds (0 = unlimited, default).
    /// A background task runs every 60 s and forcibly disconnects tunnels older than
    /// this value, logging a `tunnel.expired` audit event. Prevents forgotten tunnels
    /// from persisting indefinitely — recommended for shared government deployments.
    #[arg(long, default_value_t = 0, env = "SEAMLESS_TUNNEL_MAX_AGE")]
    tunnel_max_age: u64,
}

/// Merge file-config values into `args` for any field that still holds its
/// compile-time default (i.e., was not explicitly supplied on the CLI).
///
/// For optional fields (`Option<T>`), we set from the file if `None`.
/// For required fields we compare against the compile-time default string and
/// replace if the file supplies something different — this lets operators set
/// base_domain, ports, etc. in the config file without repeating them every
/// time they start the relay.
fn apply_file_config(args: &mut Args, cfg: &FileConfig) {
    // Required fields with defaults — replace only when still at the hardcoded default.
    if args.seam_addr == "0.0.0.0:4443".parse().unwrap() {
        if let Some(ref v) = cfg.seam_addr {
            if let Ok(a) = v.parse() { args.seam_addr = a; }
        }
    }
    if args.http_addr == "0.0.0.0:8080".parse().unwrap() {
        if let Some(ref v) = cfg.http_addr {
            if let Ok(a) = v.parse() { args.http_addr = a; }
        }
    }
    if args.admin_addr == "0.0.0.0:8088".parse().unwrap() {
        if let Some(ref v) = cfg.admin_addr {
            if let Ok(a) = v.parse() { args.admin_addr = a; }
        }
    }
    if args.base_domain == "localhost" {
        if let Some(ref v) = cfg.base_domain { args.base_domain = v.clone(); }
    }
    if args.store == "seamless-relay.json" {
        if let Some(ref v) = cfg.store { args.store = v.clone(); }
    }
    if args.log_level == "info" {
        if let Some(ref v) = cfg.log_level { args.log_level = v.clone(); }
    }
    if args.log_format == "text" {
        if let Some(ref v) = cfg.log_format { args.log_format = v.clone(); }
    }
    if args.cipher == "chacha20poly1305" {
        if let Some(ref v) = cfg.cipher { args.cipher = v.clone(); }
    }
    if args.max_tunnels_per_ip == 10 {
        if let Some(v) = cfg.max_tunnels_per_ip { args.max_tunnels_per_ip = v; }
    }
    if args.rate_limit == 10 {
        if let Some(v) = cfg.rate_limit { args.rate_limit = v; }
    }
    if args.max_tunnels == 1000 {
        if let Some(v) = cfg.max_tunnels { args.max_tunnels = v; }
    }
    if !args.tls_self_signed {
        if let Some(v) = cfg.tls_self_signed { args.tls_self_signed = v; }
    }
    // Optional fields — set from file if not already set by CLI/env.
    if args.auth_file.is_none() {
        if let Some(ref v) = cfg.auth_file { args.auth_file = Some(v.clone()); }
    }
    if args.admin_token.is_none() {
        if let Some(ref v) = cfg.admin_token { args.admin_token = Some(v.clone()); }
    }
    if args.https_addr.is_none() {
        if let Some(ref v) = cfg.https_addr {
            if let Ok(a) = v.parse() { args.https_addr = Some(a); }
        }
    }
    if args.tls_cert.is_none() {
        if let Some(ref v) = cfg.tls_cert { args.tls_cert = Some(v.clone()); }
    }
    if args.tls_key.is_none() {
        if let Some(ref v) = cfg.tls_key { args.tls_key = Some(v.clone()); }
    }
    if args.webhook_url.is_none() {
        if let Some(ref v) = cfg.webhook_url { args.webhook_url = Some(v.clone()); }
    }
    if args.admin_allow_cidr.is_none() {
        if let Some(ref v) = cfg.admin_allow_cidr { args.admin_allow_cidr = Some(v.clone()); }
    }
    if args.admin_tls_cert.is_none() {
        if let Some(ref v) = cfg.admin_tls_cert { args.admin_tls_cert = Some(v.clone()); }
    }
    if args.admin_tls_key.is_none() {
        if let Some(ref v) = cfg.admin_tls_key { args.admin_tls_key = Some(v.clone()); }
    }
    if args.admin_client_ca.is_none() {
        if let Some(ref v) = cfg.admin_client_ca { args.admin_client_ca = Some(v.clone()); }
    }
    if args.reserved_subdomains.is_none() {
        if let Some(ref v) = cfg.reserved_subdomains { args.reserved_subdomains = Some(v.clone()); }
    }
    if args.subdomain_prefix.is_none() {
        if let Some(ref v) = cfg.subdomain_prefix { args.subdomain_prefix = Some(v.clone()); }
    }
    if args.subdomain_length == 8 {
        if let Some(v) = cfg.subdomain_length { args.subdomain_length = v; }
    }
    if args.tunnel_max_age == 0 {
        if let Some(v) = cfg.tunnel_max_age { args.tunnel_max_age = v; }
    }
}

// ── CIDR helpers ──────────────────────────────────────────────────────────────

/// Parse a CIDR string like "10.0.0.0/8" into a (network, mask) pair of u32.
/// Returns `None` if the string is malformed.
pub fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_len_str) = s.trim().split_once('/')?;
    let prefix_len: u32 = prefix_len_str.parse().ok().filter(|&n| n <= 32)?;
    let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    Some((ip_u32 & mask, mask))
}

/// Returns `true` if `ip` falls within any of the given CIDRs.
/// An empty list means "allow all". IPv6 addresses are denied when any
/// IPv4 CIDRs are configured.
pub fn ip_in_cidr(ip: std::net::IpAddr, cidrs: &[(u32, u32)]) -> bool {
    if cidrs.is_empty() {
        return true; // no restriction
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            let ip_u32 = u32::from(v4);
            cidrs.iter().any(|(net, mask)| ip_u32 & mask == *net)
        }
        // IPv6 — if CIDRs are all IPv4, deny IPv6 for safety
        std::net::IpAddr::V6(_) => false,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install ring as the default rustls crypto provider before any TLS code runs.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = Args::parse();

    // Load config file and merge into args (CLI flags take priority over file values).
    let (file_cfg, config_file_path) = load_file_config(args.config.as_ref());
    apply_file_config(&mut args, &file_cfg);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("{},seamless_relay=debug", args.log_level).into());
    if args.log_format == "json" {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    let store_path = Arc::new(PathBuf::from(&args.store));
    let store = store::load(&store_path).await?;

    let identity = load_or_create_identity(&store, &store_path).await?;

    let x25519_pk_hex = hex::encode(identity.x25519_public.as_bytes());
    let kem_pk_hex = hex::encode(pk_to_bytes(&identity.kem_pk));

    info!("relay identity loaded (persistent)");
    info!("  seam-pubkey-x25519 {}", x25519_pk_hex);
    info!("  seam-pubkey-kem    {}", kem_pk_hex);
    info!(
        "connect: seamless http <port> --relay {} --x25519 {} --kem {}",
        args.seam_addr, x25519_pk_hex, kem_pk_hex
    );

    let auth = match &args.auth_file {
        Some(p) => {
            let a = AuthPolicy::from_file(p)?;
            info!("auth: token file loaded from {}", p.display());
            a
        }
        None => {
            warn!("auth: OPEN — no --auth-file set");
            AuthPolicy::open()
        }
    };

    let tunnels: TunnelMap = Arc::new(Mutex::new(HashMap::new()));
    let tcp_ports: TcpPortSet = Arc::new(Mutex::new(HashSet::new()));

    let admin_cidrs: Vec<(u32, u32)> = args.admin_allow_cidr
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(parse_cidr)
        .collect();
    if !admin_cidrs.is_empty() {
        info!("admin: IP allowlist active ({} CIDR(s) configured)", admin_cidrs.len());
    } else {
        info!("admin: no IP allowlist configured — all IPs permitted");
    }

    // Parse reserved subdomains list.
    let reserved_subdomains = {
        let list: Vec<String> = args.reserved_subdomains
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            info!(
                "subdomain reservation: {} name(s) blocked: {}",
                list.len(),
                list.join(", ")
            );
        }
        ReservedSubdomains::new(list)
    };

    // Parse subdomain prefix requirement.
    let subdomain_prefix = {
        let p = args.subdomain_prefix.as_ref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
        if let Some(ref pstr) = p {
            info!("subdomain prefix: all client-requested subdomains must start with '{pstr}'");
        }
        SubdomainPrefix::new(p)
    };

    // Clamp subdomain length to a safe minimum.
    let subdomain_length = args.subdomain_length.max(6);
    if subdomain_length != 8 {
        info!("subdomain random length: {subdomain_length} chars");
    }

    // Tunnel max-age setting.
    if args.tunnel_max_age > 0 {
        info!(
            "tunnel max-age: {}s — tunnels older than this will be expired automatically",
            args.tunnel_max_age
        );
    }

    let state = AppState {
        store,
        store_path,
        tunnels: tunnels.clone(),
        tcp_ports: tcp_ports.clone(),
        base_domain: Arc::new(args.base_domain.clone()),
        relay_pubkeys: Arc::new(RelayPubkeys {
            x25519: x25519_pk_hex,
            kem: kem_pk_hex,
        }),
        seam_addr: args.seam_addr.to_string(),
        http_port: args.http_addr.port(),
        https_port: args.https_addr.map(|a| a.port()),
        auth,
        http_client: reqwest::Client::new(),
        log_buffer: logs::new_buffer(),
        metrics: metrics::new_metrics(),
        start_time: Arc::new(Instant::now()),
        admin_token: Arc::new(args.admin_token),
        cipher: Arc::new(args.cipher.clone()),
        auth_file: Arc::new(args.auth_file.clone()),
        webhook_url: Arc::new(args.webhook_url.clone()),
        max_tunnels_per_ip: args.max_tunnels_per_ip,
        max_tunnels: args.max_tunnels,
        rate_limiter: RateLimiter::new(args.rate_limit, Duration::from_secs(60)),
        admin_cidrs: Arc::new(admin_cidrs),
        config_file: Arc::new(config_file_path),
        reserved_subdomains,
        subdomain_prefix,
        subdomain_length,
        tunnel_max_age: args.tunnel_max_age,
    };

    // Warn if admin port is publicly bound without an IP allowlist.
    if args.admin_addr.ip().is_unspecified() && state.admin_cidrs.is_empty() {
        warn!(
            "admin UI bound to {} with no --admin-allow-cidr restriction — \
             restrict access with: --admin-allow-cidr 127.0.0.1/32",
            args.admin_addr
        );
    }

    // Build optional admin TLS/mTLS configuration.
    let admin_tls = match (&args.admin_tls_cert, &args.admin_tls_key) {
        (Some(cert), Some(key)) => {
            let mtls = args.admin_client_ca.is_some();
            let acceptor = tls::admin_tls_acceptor(
                cert,
                key,
                args.admin_client_ca.as_deref(),
            )?;
            if mtls {
                info!("admin mTLS: enabled — client certificates required (CA: {})", args.admin_client_ca.as_deref().unwrap_or("?"));
            } else {
                info!("admin TLS: enabled — serving admin port over TLS 1.3");
            }
            Some(admin::AdminTlsConfig { acceptor, mtls })
        }
        (None, None) => None,
        _ => {
            return Err(anyhow::anyhow!(
                "--admin-tls-cert and --admin-tls-key must both be set (or neither)"
            ));
        }
    };

    // Start admin UI server.
    let admin_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = admin::start_admin(args.admin_addr, admin_state, admin_tls).await {
            tracing::error!("admin server died: {e:#}");
        }
    });

    // Start HTTP ingress.
    let ingress_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = ingress::run_http_ingress(args.http_addr, ingress_state).await {
            tracing::error!("http ingress died: {e:#}");
        }
    });

    // Start HTTPS ingress if configured.
    if let Some(https_addr) = args.https_addr {
        let acceptor = if args.tls_self_signed {
            tls::self_signed_acceptor(&[&args.base_domain])
                .context("failed to generate self-signed TLS cert")?
        } else if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
            tls::acceptor_from_files(cert, key)
                .with_context(|| format!("failed to load TLS cert from '{cert}' / key from '{key}'"))?
        } else {
            return Err(anyhow!(
                "--https-addr requires either --tls-self-signed or both --tls-cert and --tls-key"
            ));
        };
        info!("tls: starting https ingress on {https_addr}");
        let https_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = ingress::run_https_ingress(https_addr, acceptor, https_state).await {
                tracing::error!("https ingress died: {e:#}");
            }
        });
    }

    // SIGHUP → hot-reload the auth token file (Unix only).
    #[cfg(unix)]
    {
        let auth = state.auth.clone();
        let auth_file = state.auth_file.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP handler");
            loop {
                sighup.recv().await;
                if let Some(path) = auth_file.as_ref() {
                    match auth.reload_from_file(path) {
                        Ok(()) => info!("SIGHUP: auth file reloaded from {}", path.display()),
                        Err(e) => warn!("SIGHUP: auth reload failed: {e:#}"),
                    }
                } else {
                    info!("SIGHUP: no auth file configured, nothing to reload");
                }
            }
        });
    }

    // Tunnel expiry background task — runs every 60 s, disconnects tunnels older than max-age.
    if args.tunnel_max_age > 0 {
        let tunnels_for_expiry = tunnels.clone();
        let max_age = args.tunnel_max_age;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // discard the immediate first tick
            loop {
                interval.tick().await;
                let now = crate::store::unix_now();
                let mut map = tunnels_for_expiry.lock().await;
                let expired: Vec<_> = map
                    .iter()
                    .filter(|(_, e)| {
                        let age = now.saturating_sub(e.connected_at) as u64;
                        age >= max_age
                    })
                    .map(|(k, e)| (k.clone(), e.clone()))
                    .collect();
                for (key, entry) in expired {
                    let age = now.saturating_sub(entry.connected_at) as u64;
                    tracing::info!(
                        event = "tunnel.expired",
                        subdomain = %entry.subdomain,
                        client_ip = %entry.client_ip,
                        age_secs = age,
                        max_age_secs = max_age,
                        "tunnel '{}' from {} expired after {}s (max-age {}s)",
                        entry.subdomain, entry.client_ip, age, max_age
                    );
                    let mut tx_guard = entry.disconnect_tx.lock().await;
                    if let Some(tx) = tx_guard.take() {
                        let _ = tx.send(());
                    }
                    drop(tx_guard);
                    map.remove(&key);
                }
            }
        });
    }

    // SIGTERM → disconnect all active tunnels and shut down gracefully (Unix only).
    #[cfg(unix)]
    {
        let tunnels_for_shutdown = tunnels.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
            sigterm.recv().await;
            info!("SIGTERM received — disconnecting all tunnels and shutting down");
            // Send disconnect signal to every active tunnel.
            let mut map = tunnels_for_shutdown.lock().await;
            for entry in map.values() {
                if let Some(tx) = entry.disconnect_tx.lock().await.take() {
                    let _ = tx.send(());
                }
            }
            map.clear();
            drop(map);
            // Give in-flight connections time to drain before exiting.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            std::process::exit(0);
        });
    }

    // Seam server accept loop.
    let cipher = seam_protocol::crypto::CipherSuite::parse(&args.cipher).unwrap_or_default();
    let mut server = Server::bind_with_cipher(args.seam_addr, identity, cipher)
        .await
        .map_err(|e| anyhow!("seam bind failed: {e}"))?;
    info!("seam server listening on udp://{}", args.seam_addr);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c — shutting down gracefully");
                break;
            }
            conn = server.accept() => {
                let Some(conn) = conn else { break };
                let remote = conn.remote_addr().await;
                info!("seam connection from {remote}");
                let client_ip = remote.ip().to_string();
                let mux = SeamMux::new(conn);
                let s = state.clone();
                tokio::spawn(async move {
                    let ctx = tunnel::ConnCtx {
                        tunnels: s.tunnels,
                        tcp_ports: s.tcp_ports,
                        base_domain: (*s.base_domain).clone(),
                        http_port: s.http_port,
                        https_port: s.https_port,
                        auth: s.auth,
                        metrics: s.metrics,
                        client_ip,
                        webhook_url: (*s.webhook_url).clone().map(Arc::new),
                        http_client: s.http_client.clone(),
                        max_tunnels_per_ip: s.max_tunnels_per_ip,
                        max_tunnels: s.max_tunnels,
                        rate_limiter: s.rate_limiter,
                        reserved_subdomains: s.reserved_subdomains,
                        subdomain_prefix: s.subdomain_prefix,
                        subdomain_length: s.subdomain_length,
                    };
                    if let Err(e) = tunnel::handle_client(mux, ctx).await {
                        warn!("client from {remote} ended: {e:#}");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn load_or_create_identity(
    store: &SharedStore,
    store_path: &Arc<PathBuf>,
) -> Result<IdentityKeypair> {
    // Try loading from the compact identity blob (v0.2+).
    let saved_hex = store.read().await.identity_hex.clone();

    if let Some(hex) = saved_hex {
        let bytes = hex::decode(&hex).map_err(|_| anyhow!("invalid identity hex in store"))?;
        let identity = IdentityKeypair::from_bytes(&bytes)
            .ok_or_else(|| anyhow!("corrupt identity in store — delete seamless-relay.json to regenerate"))?;
        info!("loaded persistent relay identity from store");
        return Ok(identity);
    }

    // Generate a fresh identity and persist it.
    let identity = IdentityKeypair::generate();
    store.write().await.identity_hex = Some(hex::encode(identity.to_bytes()));
    store::save(store, store_path).await?;
    info!("generated and saved new relay identity");
    Ok(identity)
}
