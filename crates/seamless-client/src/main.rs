use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use seamless_common::{read_frame, write_frame, ControlFrame, TunnelKind, PROTOCOL_VERSION};
use seam_protocol::api::Client;
use seam_protocol::handshake::{IdentityKeypair, KemPublicKey, pk_from_bytes};
use seam_protocol::tunnel::{SeamMux, SeamStream};
use clap::{Parser, Subcommand};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "seamless", about = "Seamless — reverse tunnel client")]
struct Args {
    /// Relay UDP address.
    #[arg(long, default_value = "127.0.0.1:4443")]
    relay: SocketAddr,

    /// Relay X25519 static public key, hex-encoded.
    #[arg(long)]
    x25519: String,

    /// Relay ML-KEM-768 public key, hex-encoded.
    #[arg(long)]
    kem: String,

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
        /// Optional explicit subdomain to request.
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
}

impl Cmd {
    fn to_kind(&self) -> TunnelKind {
        match self {
            Cmd::Http { subdomain, .. } => TunnelKind::Http {
                subdomain: subdomain.clone(),
            },
            Cmd::Tcp { remote_port, .. } => TunnelKind::Tcp { port: *remote_port },
        }
    }

    fn local_target(&self) -> String {
        match self {
            Cmd::Http { port, .. } | Cmd::Tcp { port, .. } => format!("127.0.0.1:{port}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{},seamless_client=debug", args.log_level).into()
            }),
        )
        .init();
    let x25519_pk = parse_x25519(&args.x25519)?;
    let kem_pk = parse_kem(&args.kem)?;

    let local_target = args.cmd.local_target();
    let kind = args.cmd.to_kind();

    let mut backoff = Duration::from_secs(1);
    let mut attempts = 0u32;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c — exiting");
                return Ok(());
            }
            r = run_session(
                args.relay,
                &x25519_pk,
                &kem_pk,
                args.token.clone(),
                kind.clone(),
                local_target.clone(),
            ) => {
                match r {
                    Ok(()) => {
                        info!("session ended cleanly; reconnecting");
                        backoff = Duration::from_secs(1);
                    }
                    Err(e) => {
                        attempts += 1;
                        warn!("session error: {e:#}");
                        if args.max_retries != 0 && attempts >= args.max_retries {
                            bail!("giving up after {attempts} attempts");
                        }
                        warn!("reconnecting in {:?} (attempt {})", backoff, attempts + 1);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                        continue;
                    }
                }
            }
        }
    }
}

async fn run_session(
    relay: SocketAddr,
    x25519_pk: &[u8; 32],
    kem_pk: &KemPublicKey,
    token: Option<String>,
    kind: TunnelKind,
    local_target: String,
) -> Result<()> {
    // Fresh client identity per session. The relay authenticates its OWN
    // identity to the client via the static x25519/kem pubkeys; the client's
    // long-term identity is not meaningful to the relay.
    let identity = IdentityKeypair::generate();
    let mut client = Client::bind("0.0.0.0:0".parse().unwrap(), identity)
        .await
        .map_err(|e| anyhow!("seam bind: {e}"))?;

    info!("connecting to relay {} …", relay);
    let conn = client
        .connect(relay, x25519_pk, kem_pk)
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
            bail!("relay refused: {code} {message}");
        }
        other => bail!("unexpected reply: {other:?}"),
    }

    let control_task = tokio::spawn(async move {
        let mut drain = [0u8; 256];
        loop {
            match control.read(&mut drain).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
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
