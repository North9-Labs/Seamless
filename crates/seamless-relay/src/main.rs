use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use seam_protocol::api::Server;
use seam_protocol::handshake::{pk_to_bytes, IdentityKeypair};
use seam_protocol::tunnel::SeamMux;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

mod acme;
mod admin;
mod audit;
mod cloudflare;
mod denylist;
mod geoip;
mod ingress;
mod logs;
mod metrics;
mod store;
mod tcp_passthrough;
mod tls;
mod tunnel;

use audit::AuditLog;
use denylist::IpDenyList;
use geoip::GeoipFilter;
use logs::LogBuffer;
use metrics::Metrics;
use store::SharedStore;
use tcp_passthrough::TcpPassthroughConfig;
use tunnel::{
    AuthPolicy, CustomDomainMap, RateLimiter, ReservedSubdomains, SubdomainBlocklist,
    SubdomainPrefix, TcpPortSet, TunnelMap,
};

// ── Stats history ring buffer ─────────────────────────────────────────────────

/// One snapshot of relay statistics captured every 60 s.
#[derive(Clone, serde::Serialize)]
pub struct StatsSnapshot {
    /// Unix timestamp (seconds) when the snapshot was taken.
    pub ts: i64,
    /// Number of active tunnels at snapshot time.
    pub active_tunnels: u64,
    /// Cumulative connection counter at snapshot time.
    pub total_connections: u64,
}

/// A 60-entry ring buffer of `StatsSnapshot`, shared across tasks.
#[derive(Clone)]
pub struct StatsHistory {
    inner: Arc<Mutex<std::collections::VecDeque<StatsSnapshot>>>,
}

impl Default for StatsHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsHistory {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(60))),
        }
    }

    pub async fn push(&self, snap: StatsSnapshot) {
        let mut buf = self.inner.lock().await;
        if buf.len() >= 60 {
            buf.pop_front();
        }
        buf.push_back(snap);
    }

    pub async fn snapshot(&self) -> Vec<StatsSnapshot> {
        self.inner.lock().await.iter().cloned().collect()
    }
}

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
    /// Rolling 60-entry ring buffer of per-minute stats snapshots.
    pub stats_history: StatsHistory,
    /// Max proxied HTTP request body size in bytes (0 = unlimited).
    pub max_body_bytes: u64,
    /// File-backed blocklist of subdomains (reloaded on SIGHUP).
    pub blocklist: SubdomainBlocklist,
    /// IP CIDR deny list — blocks tunnel registrations from known-bad ranges.
    /// Checked before rate limiting. Reloaded on SIGHUP.
    pub ip_denylist: IpDenyList,
    /// Append-only JSONL audit log file handle (None = disabled).
    pub audit_log: AuditLog,
    /// Keepalive interval in seconds for tunnel control streams.
    /// 0 = disabled (uses the existing 25s ping). When set, the relay sends a
    /// keepalive frame if no data has flowed in the interval and disconnects
    /// if the client does not respond within 10 s.
    pub tunnel_keepalive: u64,
    /// Custom domain → tunnel_id map (Feature 2: SNI-based custom domain routing).
    pub custom_domains: CustomDomainMap,
    /// When true, clients may register any custom domain (no allowlist check).
    pub allow_custom_domains: bool,
    /// Explicit allowlist of custom domains allowed for registration.
    pub custom_domain_allowlist: Arc<std::collections::HashSet<String>>,
    /// Geo-IP country filter (Feature 4). Applied to all inbound connections.
    pub geoip: Arc<GeoipFilter>,
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
    max_body_size: Option<u64>,
    blocklist_file: Option<PathBuf>,
    ip_denylist_file: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    tunnel_keepalive: Option<u64>,
    acme_email: Option<String>,
    acme_domains: Option<String>,
    acme_dir: Option<PathBuf>,
    cloudflare_api_token: Option<String>,
    acme_production: Option<bool>,
    allow_custom_domains: Option<bool>,
    custom_domain_allowlist: Option<String>,
    tcp_passthrough: Option<Vec<String>>,
    geoip_db: Option<String>,
    block_countries: Option<String>,
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

    /// Maximum proxied HTTP request body size in bytes (0 = unlimited, default 10485760 = 10 MiB).
    /// Requests whose bodies exceed this limit are rejected with 413 Content Too Large
    /// before they reach the tunnel backend, preventing memory exhaustion attacks.
    #[arg(long, default_value_t = 10 * 1024 * 1024, env = "SEAMLESS_MAX_BODY_SIZE")]
    max_body_size: u64,

    /// Path to a newline-separated file of blocked subdomains.
    /// Lines starting with '#' and blank lines are ignored.
    /// Reloaded automatically on SIGHUP — no restart needed.
    /// Useful for large lists (thousands of entries) of phishing names,
    /// brand-squatting patterns, or otherwise forbidden subdomains.
    /// Complements --reserved-subdomains (which is CLI-sized).
    #[arg(long, env = "SEAMLESS_BLOCKLIST_FILE")]
    blocklist_file: Option<PathBuf>,

    /// Path to a newline-separated file of CIDR ranges blocked from opening tunnels.
    /// Lines beginning with '#' and blank lines are ignored (e.g. "10.0.0.0/8").
    /// Checked before rate limiting — matching IPs receive an immediate 403.
    /// Reloaded automatically on SIGHUP — no restart needed.
    /// Useful for blocking known bad ASNs, Tor exit nodes, or hostile ranges
    /// in government and classified deployments.
    #[arg(long, env = "SEAMLESS_IP_DENYLIST_FILE")]
    ip_denylist_file: Option<PathBuf>,

    /// Path for the append-only JSONL audit log file.
    /// Every structured audit event (tunnel open/close, auth failures, admin
    /// actions, IP denylist hits, etc.) is appended as one JSON line.
    /// Rotated at midnight UTC: the current file is renamed to
    /// <path>.YYYY-MM-DD and a fresh file is opened.
    /// Required for government compliance (persistent, immutable audit trail).
    #[arg(long, env = "SEAMLESS_AUDIT_LOG")]
    audit_log: Option<PathBuf>,

    /// Tunnel keepalive interval in seconds (0 = disabled, default 30).
    /// The relay sends a keepalive frame on the tunnel control stream if no
    /// data has flowed within this interval.  If the client does not respond
    /// within 10 seconds the tunnel is torn down and a `tunnel.keepalive_timeout`
    /// audit event is emitted.  Useful for detecting dead NAT-traversed clients
    /// faster than TCP keepalive allows.
    #[arg(long, default_value_t = 30, env = "SEAMLESS_TUNNEL_KEEPALIVE")]
    tunnel_keepalive: u64,

    // ── Feature 1: ACME / Let's Encrypt ──────────────────────────────────────
    /// Email address for Let's Encrypt account registration.
    #[arg(long, env = "SEAMLESS_ACME_EMAIL")]
    acme_email: Option<String>,

    /// Comma-separated list of domains for the ACME certificate.
    #[arg(long, env = "SEAMLESS_ACME_DOMAINS")]
    acme_domains: Option<String>,

    /// Directory for ACME account keys and certificates (default: ~/.local/share/seamless/acme).
    #[arg(long, env = "SEAMLESS_ACME_DIR")]
    acme_dir: Option<PathBuf>,

    /// Cloudflare API token for DNS-01 ACME challenge. When not set, HTTP-01 is used.
    #[arg(long, env = "CLOUDFLARE_API_TOKEN")]
    cloudflare_api_token: Option<String>,

    /// Use the Let's Encrypt production CA (default: staging).
    #[arg(long, default_value_t = false)]
    acme_production: bool,

    // ── Feature 2: Custom Domain Support ─────────────────────────────────────
    /// Allow clients to register any custom domain (SNI/Host routing).
    /// Without this flag, only domains in --custom-domain-allowlist are accepted.
    #[arg(long, default_value_t = false, env = "SEAMLESS_ALLOW_CUSTOM_DOMAINS")]
    allow_custom_domains: bool,

    /// Comma-separated list of allowed custom domains for client registration.
    #[arg(long, env = "SEAMLESS_CUSTOM_DOMAIN_ALLOWLIST")]
    custom_domain_allowlist: Option<String>,

    // ── Feature 3: TCP Passthrough ────────────────────────────────────────────
    /// Forward raw TCP connections to a backend without HTTP parsing.
    /// Format: <listen_port>:<backend_host>:<backend_port>
    /// Can be repeated for multiple passthrough rules.
    /// Example: --tcp-passthrough 5432:db.internal:5432 --tcp-passthrough 6379:redis.internal:6379
    #[arg(
        long = "tcp-passthrough",
        value_name = "PORT:HOST:PORT",
        env = "SEAMLESS_TCP_PASSTHROUGH"
    )]
    tcp_passthrough: Vec<String>,

    // ── Feature 4: Geo-IP Country Blocking ───────────────────────────────────
    /// Path to a MaxMind GeoLite2-Country.mmdb file for geo-IP blocking.
    /// Required when --block-countries is set. Without this flag, geo-blocking
    /// is disabled and a warning is emitted.
    #[arg(long, env = "SEAMLESS_GEOIP_DB")]
    geoip_db: Option<String>,

    /// Comma-separated ISO 3166-1 alpha-2 country codes to block.
    /// Example: --block-countries CN,RU,KP,IR
    /// Requires --geoip-db. Affects both TCP passthrough and HTTP ingress.
    #[arg(long, env = "SEAMLESS_BLOCK_COUNTRIES")]
    block_countries: Option<String>,
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
            if let Ok(a) = v.parse() {
                args.seam_addr = a;
            }
        }
    }
    if args.http_addr == "0.0.0.0:8080".parse().unwrap() {
        if let Some(ref v) = cfg.http_addr {
            if let Ok(a) = v.parse() {
                args.http_addr = a;
            }
        }
    }
    if args.admin_addr == "0.0.0.0:8088".parse().unwrap() {
        if let Some(ref v) = cfg.admin_addr {
            if let Ok(a) = v.parse() {
                args.admin_addr = a;
            }
        }
    }
    if args.base_domain == "localhost" {
        if let Some(ref v) = cfg.base_domain {
            args.base_domain = v.clone();
        }
    }
    if args.store == "seamless-relay.json" {
        if let Some(ref v) = cfg.store {
            args.store = v.clone();
        }
    }
    if args.log_level == "info" {
        if let Some(ref v) = cfg.log_level {
            args.log_level = v.clone();
        }
    }
    if args.log_format == "text" {
        if let Some(ref v) = cfg.log_format {
            args.log_format = v.clone();
        }
    }
    if args.cipher == "chacha20poly1305" {
        if let Some(ref v) = cfg.cipher {
            args.cipher = v.clone();
        }
    }
    if args.max_tunnels_per_ip == 10 {
        if let Some(v) = cfg.max_tunnels_per_ip {
            args.max_tunnels_per_ip = v;
        }
    }
    if args.rate_limit == 10 {
        if let Some(v) = cfg.rate_limit {
            args.rate_limit = v;
        }
    }
    if args.max_tunnels == 1000 {
        if let Some(v) = cfg.max_tunnels {
            args.max_tunnels = v;
        }
    }
    if !args.tls_self_signed {
        if let Some(v) = cfg.tls_self_signed {
            args.tls_self_signed = v;
        }
    }
    // Optional fields — set from file if not already set by CLI/env.
    if args.auth_file.is_none() {
        if let Some(ref v) = cfg.auth_file {
            args.auth_file = Some(v.clone());
        }
    }
    if args.admin_token.is_none() {
        if let Some(ref v) = cfg.admin_token {
            args.admin_token = Some(v.clone());
        }
    }
    if args.https_addr.is_none() {
        if let Some(ref v) = cfg.https_addr {
            if let Ok(a) = v.parse() {
                args.https_addr = Some(a);
            }
        }
    }
    if args.tls_cert.is_none() {
        if let Some(ref v) = cfg.tls_cert {
            args.tls_cert = Some(v.clone());
        }
    }
    if args.tls_key.is_none() {
        if let Some(ref v) = cfg.tls_key {
            args.tls_key = Some(v.clone());
        }
    }
    if args.webhook_url.is_none() {
        if let Some(ref v) = cfg.webhook_url {
            args.webhook_url = Some(v.clone());
        }
    }
    if args.admin_allow_cidr.is_none() {
        if let Some(ref v) = cfg.admin_allow_cidr {
            args.admin_allow_cidr = Some(v.clone());
        }
    }
    if args.admin_tls_cert.is_none() {
        if let Some(ref v) = cfg.admin_tls_cert {
            args.admin_tls_cert = Some(v.clone());
        }
    }
    if args.admin_tls_key.is_none() {
        if let Some(ref v) = cfg.admin_tls_key {
            args.admin_tls_key = Some(v.clone());
        }
    }
    if args.admin_client_ca.is_none() {
        if let Some(ref v) = cfg.admin_client_ca {
            args.admin_client_ca = Some(v.clone());
        }
    }
    if args.reserved_subdomains.is_none() {
        if let Some(ref v) = cfg.reserved_subdomains {
            args.reserved_subdomains = Some(v.clone());
        }
    }
    if args.subdomain_prefix.is_none() {
        if let Some(ref v) = cfg.subdomain_prefix {
            args.subdomain_prefix = Some(v.clone());
        }
    }
    if args.subdomain_length == 8 {
        if let Some(v) = cfg.subdomain_length {
            args.subdomain_length = v;
        }
    }
    if args.tunnel_max_age == 0 {
        if let Some(v) = cfg.tunnel_max_age {
            args.tunnel_max_age = v;
        }
    }
    if args.max_body_size == 10 * 1024 * 1024 {
        if let Some(v) = cfg.max_body_size {
            args.max_body_size = v;
        }
    }
    if args.blocklist_file.is_none() {
        if let Some(ref v) = cfg.blocklist_file {
            args.blocklist_file = Some(v.clone());
        }
    }
    if args.ip_denylist_file.is_none() {
        if let Some(ref v) = cfg.ip_denylist_file {
            args.ip_denylist_file = Some(v.clone());
        }
    }
    if args.audit_log.is_none() {
        if let Some(ref v) = cfg.audit_log {
            args.audit_log = Some(v.clone());
        }
    }
    if args.tunnel_keepalive == 30 {
        if let Some(v) = cfg.tunnel_keepalive {
            args.tunnel_keepalive = v;
        }
    }
    if args.acme_email.is_none() {
        if let Some(ref v) = cfg.acme_email {
            args.acme_email = Some(v.clone());
        }
    }
    if args.acme_domains.is_none() {
        if let Some(ref v) = cfg.acme_domains {
            args.acme_domains = Some(v.clone());
        }
    }
    if args.acme_dir.is_none() {
        if let Some(ref v) = cfg.acme_dir {
            args.acme_dir = Some(v.clone());
        }
    }
    if args.cloudflare_api_token.is_none() {
        if let Some(ref v) = cfg.cloudflare_api_token {
            args.cloudflare_api_token = Some(v.clone());
        }
    }
    if !args.acme_production {
        if let Some(v) = cfg.acme_production {
            args.acme_production = v;
        }
    }
    if !args.allow_custom_domains {
        if let Some(v) = cfg.allow_custom_domains {
            args.allow_custom_domains = v;
        }
    }
    if args.custom_domain_allowlist.is_none() {
        if let Some(ref v) = cfg.custom_domain_allowlist {
            args.custom_domain_allowlist = Some(v.clone());
        }
    }
    if args.tcp_passthrough.is_empty() {
        if let Some(ref v) = cfg.tcp_passthrough {
            args.tcp_passthrough = v.clone();
        }
    }
    if args.geoip_db.is_none() {
        if let Some(ref v) = cfg.geoip_db {
            args.geoip_db = Some(v.clone());
        }
    }
    if args.block_countries.is_none() {
        if let Some(ref v) = cfg.block_countries {
            args.block_countries = Some(v.clone());
        }
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
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
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
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
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
    let custom_domains: CustomDomainMap = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

    // Parse custom domain allowlist.
    let custom_domain_allowlist: std::collections::HashSet<String> = args
        .custom_domain_allowlist
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if args.allow_custom_domains {
        info!("custom-domains: open mode — clients may register any custom domain");
    } else if !custom_domain_allowlist.is_empty() {
        info!(
            "custom-domains: allowlist mode ({} domain(s))",
            custom_domain_allowlist.len()
        );
    }

    let admin_cidrs: Vec<(u32, u32)> = args
        .admin_allow_cidr
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(parse_cidr)
        .collect();
    if !admin_cidrs.is_empty() {
        info!(
            "admin: IP allowlist active ({} CIDR(s) configured)",
            admin_cidrs.len()
        );
    } else {
        info!("admin: no IP allowlist configured — all IPs permitted");
    }

    // Parse reserved subdomains list.
    let reserved_subdomains = {
        let list: Vec<String> = args
            .reserved_subdomains
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
        let p = args
            .subdomain_prefix
            .as_ref()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());
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

    let stats_history = StatsHistory::new();

    if args.max_body_size > 0 {
        info!(
            "request body limit: {} bytes ({} MiB)",
            args.max_body_size,
            args.max_body_size / (1024 * 1024)
        );
    }

    // Load subdomain blocklist file if configured.
    let blocklist = match &args.blocklist_file {
        Some(path) => SubdomainBlocklist::from_file(path),
        None => SubdomainBlocklist::disabled(),
    };

    // Load IP CIDR deny list if configured.
    let ip_denylist = match &args.ip_denylist_file {
        Some(path) => {
            info!("ip-denylist: loading from {}", path.display());
            IpDenyList::from_file(path)
        }
        None => IpDenyList::disabled(),
    };

    // Start audit log writer if configured.
    let audit_log = match &args.audit_log {
        Some(path) => {
            info!("audit-log: writing to {}", path.display());
            AuditLog::start(path.clone())
        }
        None => {
            info!("audit-log: not configured (use --audit-log <path> for compliance logging)");
            AuditLog::disabled()
        }
    };

    // Parse TCP passthrough configs.
    let tcp_passthrough_configs: Vec<TcpPassthroughConfig> = {
        let mut cfgs = Vec::new();
        for raw in &args.tcp_passthrough {
            match TcpPassthroughConfig::parse(raw) {
                Ok(cfg) => cfgs.push(cfg),
                Err(e) => return Err(anyhow!("{e}")),
            }
        }
        cfgs
    };

    // Build geo-IP filter.
    let blocked_countries: Vec<String> = args
        .block_countries
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let geoip = Arc::new(
        GeoipFilter::new(args.geoip_db.as_deref(), blocked_countries)
            .context("failed to initialise geo-IP filter")?,
    );

    // Log tunnel keepalive setting.
    if args.tunnel_keepalive > 0 {
        info!(
            "tunnel keepalive: {}s interval, 10s response deadline",
            args.tunnel_keepalive
        );
    } else {
        info!("tunnel keepalive: disabled");
    }

    let state = AppState {
        store,
        store_path,
        tunnels: tunnels.clone(),
        tcp_ports: tcp_ports.clone(),
        custom_domains: custom_domains.clone(),
        allow_custom_domains: args.allow_custom_domains,
        custom_domain_allowlist: Arc::new(custom_domain_allowlist),
        geoip: geoip.clone(),
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
        stats_history: stats_history.clone(),
        max_body_bytes: args.max_body_size,
        blocklist: blocklist.clone(),
        ip_denylist: ip_denylist.clone(),
        audit_log: audit_log.clone(),
        tunnel_keepalive: args.tunnel_keepalive,
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
            let acceptor = tls::admin_tls_acceptor(cert, key, args.admin_client_ca.as_deref())?;
            if mtls {
                info!(
                    "admin mTLS: enabled — client certificates required (CA: {})",
                    args.admin_client_ca.as_deref().unwrap_or("?")
                );
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

    // Spawn TCP passthrough listeners.
    for cfg in tcp_passthrough_configs {
        info!(
            "tcp-passthrough: will forward port {} → {}:{}",
            cfg.listen_port, cfg.backend_host, cfg.backend_port
        );
        let pt_denylist = ip_denylist.clone();
        let pt_rate_limiter = state.rate_limiter.clone();
        let pt_geoip = geoip.clone();
        let pt_metrics = state.metrics.clone();
        let pt_audit = audit_log.clone();
        tokio::spawn(async move {
            if let Err(e) = tcp_passthrough::run_tcp_passthrough(
                cfg,
                pt_denylist,
                pt_rate_limiter,
                pt_geoip,
                pt_metrics,
                pt_audit,
            )
            .await
            {
                tracing::error!("tcp-passthrough listener died: {e:#}");
            }
        });
    }

    // Start HTTP ingress.
    let ingress_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = ingress::run_http_ingress(args.http_addr, ingress_state).await {
            tracing::error!("http ingress died: {e:#}");
        }
    });

    // Start HTTPS ingress if configured.
    if let Some(https_addr) = args.https_addr {
        let base_acceptor = if args.tls_self_signed {
            tls::self_signed_acceptor(&[&args.base_domain])
                .context("failed to generate self-signed TLS cert")?
        } else if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
            tls::acceptor_from_files(cert, key).with_context(|| {
                format!("failed to load TLS cert from '{cert}' / key from '{key}'")
            })?
        } else {
            return Err(anyhow!(
                "--https-addr requires either --tls-self-signed or both --tls-cert and --tls-key"
            ));
        };

        // Wrap in a hot-swappable acceptor so SIGUSR1 can rotate the cert.
        let hot_acceptor: ingress::HotAcceptor = Arc::new(std::sync::RwLock::new(base_acceptor));

        // SIGUSR1 → hot-reload TLS cert/key from disk without dropping connections.
        #[cfg(unix)]
        {
            let hot = hot_acceptor.clone();
            let cert_path = args.tls_cert.clone();
            let key_path = args.tls_key.clone();
            let self_signed = args.tls_self_signed;
            let base_domain_for_reload = args.base_domain.clone();
            tokio::spawn(async move {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigusr1 = match signal(SignalKind::user_defined1()) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("SIGUSR1 handler failed to register: {e}");
                        return;
                    }
                };
                loop {
                    sigusr1.recv().await;
                    info!("SIGUSR1: reloading TLS certificate from disk");
                    let result = if self_signed {
                        tls::self_signed_acceptor(&[&base_domain_for_reload])
                    } else if let (Some(ref cert), Some(ref key)) = (&cert_path, &key_path) {
                        tls::acceptor_from_files(cert, key)
                    } else {
                        warn!("SIGUSR1: no cert/key paths to reload (self-signed cert cannot be rotated)");
                        continue;
                    };
                    match result {
                        Ok(new_acceptor) => {
                            *hot.write().expect("hot acceptor RwLock poisoned") = new_acceptor;
                            info!("SIGUSR1: TLS certificate rotated successfully — new connections use new cert");
                        }
                        Err(e) => {
                            warn!(
                                "SIGUSR1: TLS cert reload failed (keeping old cert active): {e:#}"
                            );
                        }
                    }
                }
            });
        }

        info!("tls: starting https ingress on {https_addr}");
        let https_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = ingress::run_https_ingress(https_addr, hot_acceptor, https_state).await
            {
                tracing::error!("https ingress died: {e:#}");
            }
        });
    }

    // ── ACME / Let's Encrypt certificate provisioning ─────────────────────────
    if let Some(ref acme_email) = args.acme_email {
        let domains: Vec<String> = args
            .acme_domains
            .as_deref()
            .unwrap_or(&args.base_domain)
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let acme_dir = args.acme_dir.clone().unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".local/share/seamless/acme")
        });

        let acme_cfg = acme::AcmeConfig {
            email: acme_email.clone(),
            domains,
            cloudflare_api_token: args.cloudflare_api_token.clone(),
            acme_dir,
            production: args.acme_production,
        };
        info!(
            "acme: configured for domains {:?} ({})",
            acme_cfg.domains,
            if args.acme_production {
                "production"
            } else {
                "staging"
            }
        );

        let acme_client = Arc::new(acme::AcmeClient::new(acme_cfg, state.audit_log.clone()));

        // Serve ACME HTTP-01 challenge server on port 80 if no Cloudflare token.
        if args.cloudflare_api_token.is_none() {
            let tokens = acme_client.challenge_tokens.clone();
            tokio::spawn(async move {
                let addr = "0.0.0.0:80".parse().expect("valid addr");
                if let Err(e) = acme::run_acme_http_server(addr, tokens).await {
                    warn!("ACME HTTP-01 server error: {e:#}");
                }
            });
        }

        // Obtain initial certificate if needed.
        if acme_client.needs_renewal().await {
            info!("acme: obtaining initial certificate");
            match acme_client.obtain_certificate().await {
                Ok((cert_pem, key_pem)) => {
                    info!("acme: certificate obtained successfully");
                    // Store temporarily so the HTTPS ingress can pick it up.
                    // In a production system the cert_pem/key_pem would be written to
                    // tls_cert/tls_key paths so the hot acceptor can load them.
                    if let Some((cert_path, key_path)) = acme_client.cert_paths() {
                        // Write to the paths specified (already done in obtain_certificate),
                        // then trigger a reload if a hot acceptor is running.
                        let _ = (cert_pem, key_pem, cert_path, key_path);
                    }
                }
                Err(e) => {
                    warn!("acme: initial certificate failed: {e:#}");
                }
            }
        } else {
            info!("acme: existing certificate is valid");
        }

        // Spawn renewal background task.
        let (cert_tx, _cert_rx) = tokio::sync::mpsc::channel::<(String, String)>(4);
        acme::spawn_renewal_task(acme_client, cert_tx);
    }

    // SIGHUP → hot-reload the auth token file, subdomain blocklist, and IP deny list (Unix only).
    #[cfg(unix)]
    {
        let auth = state.auth.clone();
        let auth_file = state.auth_file.clone();
        let blocklist_for_sighup = blocklist.clone();
        let denylist_for_sighup = ip_denylist.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
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
                if blocklist_for_sighup.is_enabled() {
                    blocklist_for_sighup.reload();
                }
                if denylist_for_sighup.is_enabled() {
                    denylist_for_sighup.reload();
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

    // Stats history background task — captures a snapshot every 60 s.
    {
        let tunnels_for_stats = tunnels.clone();
        let metrics_for_stats = state.metrics.clone();
        let hist = stats_history.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let active_tunnels = tunnels_for_stats.lock().await.len() as u64;
                let total_connections = metrics_for_stats
                    .connections_total
                    .load(std::sync::atomic::Ordering::Relaxed);
                hist.push(StatsSnapshot {
                    ts: crate::store::unix_now(),
                    active_tunnels,
                    total_connections,
                })
                .await;
            }
        });
    }

    // SIGTERM → disconnect all active tunnels and shut down gracefully (Unix only).
    #[cfg(unix)]
    {
        let tunnels_for_shutdown = tunnels.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
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
                        blocklist: s.blocklist,
                        ip_denylist: s.ip_denylist,
                        audit_log: s.audit_log,
                        tunnel_keepalive: s.tunnel_keepalive,
                        custom_domains: s.custom_domains.clone(),
                        allow_custom_domains: s.allow_custom_domains,
                        custom_domain_allowlist: Arc::new((*s.custom_domain_allowlist).clone()),
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
        let identity = IdentityKeypair::from_bytes(&bytes).ok_or_else(|| {
            anyhow!("corrupt identity in store — delete seamless-relay.json to regenerate")
        })?;
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
