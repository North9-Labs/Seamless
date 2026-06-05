// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use seamless_common::{read_frame, write_frame, ControlFrame, TunnelKind, PROTOCOL_VERSION};
use seam_protocol::api::Client;
use seam_protocol::handshake::{IdentityKeypair, KemPublicKey, pk_from_bytes};
use seam_protocol::tunnel::{SeamMux, SeamStream};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{info, warn};

mod config;
use config::ClientConfig;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "seamless", about = "Seamless — reverse tunnel client")]
struct Args {
    /// Path to a TOML config file.  Defaults to ~/.config/seamless/config.toml.
    /// CLI flags always override values in the config file.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Relay UDP address (or set in config with `seamless config init`).
    #[arg(long)]
    relay: Option<String>,

    /// Relay X25519 static public key, hex-encoded (or set in config).
    #[arg(long)]
    x25519: Option<String>,

    /// Relay ML-KEM-768 public key, hex-encoded (or set in config).
    #[arg(long)]
    kem: Option<String>,

    /// Auth token (if the relay was started with --auth-file).
    #[arg(long)]
    token: Option<String>,

    /// Max reconnect attempts after the session drops (0 = infinite).
    #[arg(long, default_value_t = 0)]
    max_retries: u32,

    /// Log level: error, warn, info, debug, trace (overrides RUST_LOG).
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Expose a local HTTP service.
    Http {
        /// Local port serving HTTP.
        port: u16,
        /// Optional explicit subdomain to request (overrides config file `subdomain`).
        #[arg(long)]
        subdomain: Option<String>,
    },
    /// Expose a local TCP service on a relay-assigned (or requested) port.
    Tcp {
        /// Local TCP port to forward to.
        port: u16,
        /// Optional explicit relay-side port (default: relay picks one).
        #[arg(long, default_value_t = 0)]
        remote_port: u16,
    },
    /// Manage the local client configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ConfigAction {
    /// Save relay connection details so you don't have to pass them every time.
    Init {
        /// Relay UDP address (host:port).
        #[arg(long)]
        relay: Option<String>,
        /// Relay X25519 public key, hex-encoded.
        #[arg(long)]
        x25519: Option<String>,
        /// Relay ML-KEM-768 public key, hex-encoded.
        #[arg(long)]
        kem: Option<String>,
        /// Default auth token.
        #[arg(long)]
        token: Option<String>,
        /// Default subdomain (HTTP tunnels).
        #[arg(long)]
        subdomain: Option<String>,
    },
    /// Print the current configuration.
    Show,
    /// Clear all saved configuration.
    Clear,
}

impl Cmd {
    fn to_kind(&self, saved_subdomain: Option<String>) -> Option<TunnelKind> {
        match self {
            Cmd::Http { subdomain, .. } => Some(TunnelKind::Http {
                // CLI --subdomain > config file subdomain
                subdomain: subdomain.clone().or(saved_subdomain),
            }),
            Cmd::Tcp { remote_port, .. } => Some(TunnelKind::Tcp { port: *remote_port }),
            Cmd::Config { .. } => None,
        }
    }

    fn local_target(&self) -> Option<String> {
        match self {
            Cmd::Http { port, .. } | Cmd::Tcp { port, .. } => Some(format!("127.0.0.1:{port}")),
            Cmd::Config { .. } => None,
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle config subcommand before any network setup.
    if let Cmd::Config { action } = &args.cmd {
        return handle_config(action);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{},seamless_client=debug", args.log_level).into()
            }),
        )
        .init();

    // Load config file: --config path overrides default location.
    let saved = config::load_from(args.config.as_ref());

    let relay_str = args
        .relay
        .or(saved.relay)
        .ok_or_else(|| anyhow!("--relay required (or run `seamless config init --relay <addr>` to save it)"))?;
    let x25519_str = args
        .x25519
        .or(saved.x25519)
        .ok_or_else(|| anyhow!("--x25519 required (or run `seamless config init --x25519 <hex>` to save it)"))?;
    let kem_str = args
        .kem
        .or(saved.kem)
        .ok_or_else(|| anyhow!("--kem required (or run `seamless config init --kem <hex>` to save it)"))?;
    let token = args.token.or(saved.token);

    let relay: SocketAddr = relay_str
        .parse()
        .with_context(|| format!("invalid relay address: {relay_str}"))?;
    let x25519_pk = parse_x25519(&x25519_str)?;
    let kem_pk = parse_kem(&kem_str)?;

    let local_target = args.cmd.local_target()
        .ok_or_else(|| anyhow!("expected http or tcp subcommand"))?;
    let kind = args.cmd.to_kind(saved.subdomain)
        .ok_or_else(|| anyhow!("expected http or tcp subcommand"))?;

    // Generate a single ephemeral identity for this process run.
    // Reusing the same identity across reconnects gives the relay a consistent
    // peer key — useful for future per-client allowlists and audit logs.
    let identity = IdentityKeypair::generate();
    let identity_bytes = identity.to_bytes();

    // Reconnect loop with exponential backoff.
    // Schedule: immediate, 1 s, 2 s, 4 s, 8 s, 16 s, 30 s (cap).
    let mut attempts = 0u32;
    let mut backoff: Option<Duration> = None; // None = no sleep before first attempt

    loop {
        // Sleep before retry (skip on the very first attempt).
        if let Some(delay) = backoff {
            warn!(
                delay_secs = delay.as_secs(),
                attempt = attempts + 1,
                "reconnecting in {delay:?}"
            );
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("ctrl-c — exiting");
                    return Ok(());
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }

        let session_identity = IdentityKeypair::from_bytes(&identity_bytes)
            .expect("identity round-trips through bytes");

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c — exiting");
                return Ok(());
            }
            r = run_session(
                relay,
                &x25519_pk,
                &kem_pk,
                token.clone(),
                kind.clone(),
                local_target.clone(),
                session_identity,
            ) => {
                match r {
                    Ok(()) => {
                        info!("session ended cleanly; reconnecting immediately");
                        // Reset backoff on clean disconnect.
                        attempts = 0;
                        backoff = None;
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        // Permanent errors (relay refusal, auth, version mismatch) should not
                        // be retried — the operator needs to fix config.
                        if msg.contains("PERMANENT") {
                            return Err(e);
                        }
                        attempts += 1;
                        warn!("session error (attempt {attempts}): {e:#}");
                        if args.max_retries != 0 && attempts >= args.max_retries {
                            bail!("giving up after {attempts} attempts");
                        }
                        // Backoff schedule: immediate (None), 1 s, 2 s, 4 s, 8 s, 16 s, 30 s cap.
                        backoff = Some(match attempts {
                            1 => Duration::from_secs(0), // treat as immediate next iteration
                            2 => Duration::from_secs(1),
                            3 => Duration::from_secs(2),
                            4 => Duration::from_secs(4),
                            5 => Duration::from_secs(8),
                            6 => Duration::from_secs(16),
                            _ => Duration::from_secs(30),
                        });
                        // Zero-duration backoff = immediate retry (no sleep message).
                        if backoff == Some(Duration::ZERO) {
                            backoff = None;
                        }
                    }
                }
            }
        }
    }
}

// ── Config subcommand ─────────────────────────────────────────────────────────

fn handle_config(action: &ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Init { relay, x25519, kem, token, subdomain } => {
            let mut cfg = config::load();
            if relay.is_some()     { cfg.relay     = relay.clone(); }
            if x25519.is_some()    { cfg.x25519    = x25519.clone(); }
            if kem.is_some()       { cfg.kem        = kem.clone(); }
            if token.is_some()     { cfg.token      = token.clone(); }
            if subdomain.is_some() { cfg.subdomain  = subdomain.clone(); }
            config::save(&cfg)?;
            println!("config saved → {}", config::path_display());
            println!();
            if let Some(r) = &cfg.relay     { println!("  relay     = {r}"); }
            if let Some(k) = &cfg.x25519    { println!("  x25519    = {k}"); }
            if cfg.kem.is_some()             { println!("  kem       = <{} bytes>", cfg.kem.as_deref().unwrap().len() / 2); }
            if cfg.token.is_some()           { println!("  token     = <set>"); }
            if let Some(s) = &cfg.subdomain  { println!("  subdomain = {s}"); }
        }
        ConfigAction::Show => {
            let cfg = config::load();
            println!("config: {}", config::path_display());
            println!();
            println!("  relay     = {}", cfg.relay.as_deref().unwrap_or("<not set>"));
            println!("  x25519    = {}", cfg.x25519.as_deref().unwrap_or("<not set>"));
            println!("  kem       = {}", if cfg.kem.is_some() {
                format!("<{} bytes>", cfg.kem.as_deref().unwrap().len() / 2)
            } else {
                "<not set>".into()
            });
            println!("  token     = {}", if cfg.token.is_some() { "<set>" } else { "<not set>" });
            println!("  subdomain = {}", cfg.subdomain.as_deref().unwrap_or("<not set>"));
            println!("  local     = {}", cfg.local.as_deref().unwrap_or("<not set>"));
            println!("  tls_verify = {}", cfg.tls_verify);
        }
        ConfigAction::Clear => {
            config::save(&ClientConfig::default())?;
            println!("config cleared → {}", config::path_display());
        }
    }
    Ok(())
}

// ── Session ───────────────────────────────────────────────────────────────────

async fn run_session(
    relay: SocketAddr,
    x25519_pk: &[u8; 32],
    kem_pk: &KemPublicKey,
    token: Option<String>,
    kind: TunnelKind,
    local_target: String,
    identity: IdentityKeypair,
) -> Result<()> {
    let mut client = Client::bind("0.0.0.0:0".parse().expect("valid socket addr"), identity)
        .await
        .map_err(|e| anyhow!("seam bind: {e}"))?;

    info!("connecting to relay {} …", relay);
    let conn = client
        .connect(relay, x25519_pk, kem_pk, Default::default())
        .await
        .map_err(|e| anyhow!("seam connect: {e}"))?;
    info!("handshake complete");

    let mux = SeamMux::new(conn);

    let mut control = mux.open_stream().await;
    write_frame(
        &mut control,
        &ControlFrame::Register {
            version: PROTOCOL_VERSION,
            token,
            kind,
        },
    )
    .await
    .context("sending register")?;

    match read_frame(&mut control)
        .await
        .context("awaiting register reply")?
    {
        ControlFrame::Registered { public_url } => {
            println!();
            println!("  seamless tunnel ready");
            println!("    public:  {public_url}");
            println!("    local:   {local_target}");
            println!();
        }
        ControlFrame::Error { code, message } => {
            // Relay-level rejections are permanent — no retry makes them go away.
            // Use a sentinel that the reconnect loop recognises.
            bail!("PERMANENT relay refused: {code} {message}");
        }
        other => bail!("unexpected reply: {other:?}"),
    }

    // Keepalive: send Ping every 25 seconds on the idle control stream.
    let mut ping_interval = tokio::time::interval(Duration::from_secs(25));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_interval.tick().await; // discard first immediate tick

    let control_task = tokio::spawn(async move {
        let mut drain = [0u8; 256];
        loop {
            tokio::select! {
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
    });

    loop {
        let Some(stream) = mux.accept_stream().await else {
            info!("mux closed; session ending");
            break;
        };
        let target = local_target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(stream, target).await {
                warn!("forwarding error: {e:#}");
            }
        });
    }

    control_task.abort();
    Ok(())
}

async fn handle_incoming(mut apex: SeamStream, local_target: String) -> Result<()> {
    let frame = read_frame(&mut apex)
        .await
        .context("reading NewConn preamble")?;
    let peer = match frame {
        ControlFrame::NewConn { peer_addr } => peer_addr,
        other => bail!("expected NewConn, got {other:?}"),
    };
    info!(peer = %peer, target = %local_target, "new tunneled connection");

    let mut local = TcpStream::connect(&local_target)
        .await
        .with_context(|| format!("dialing local {local_target}"))?;

    let _ = tokio::io::copy_bidirectional(&mut local, &mut apex).await;
    Ok(())
}

// ── Key parsing ───────────────────────────────────────────────────────────────

fn parse_x25519(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("x25519 not hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("x25519 must be 32 bytes, got {}", bytes.len()))
}

fn parse_kem(s: &str) -> Result<KemPublicKey> {
    let bytes = hex::decode(s.trim()).context("kem key not hex")?;
    pk_from_bytes(&bytes).ok_or_else(|| anyhow!("invalid ML-KEM-768 public key ({} bytes)", bytes.len()))
}
