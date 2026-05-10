use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use seam_protocol::api::Server;
use seam_protocol::handshake::IdentityKeypair;
use seam_protocol::tunnel::SeamMux;
use clap::Parser;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use tokio::sync::Mutex;
use tracing::{info, warn};

mod admin;
mod cloudflare;
mod ingress;
mod logs;
mod store;
mod tunnel;

use logs::LogBuffer;
use store::SharedStore;
use tunnel::{AuthPolicy, TcpPortSet, TunnelMap};

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
    pub auth: AuthPolicy,
    pub http_client: reqwest::Client,
    pub log_buffer: LogBuffer,
}

pub struct RelayPubkeys {
    pub x25519: String,
    pub kem: String,
}

#[derive(Parser, Debug)]
#[command(name = "seamless-relay", about = "Seamless — PQ reverse tunnel relay")]
struct Args {
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,seamless_relay=debug".into()),
        )
        .init();

    let args = Args::parse();

    let store_path = Arc::new(PathBuf::from(&args.store));
    let store = store::load(&store_path).await?;

    let identity = load_or_create_identity(&store, &store_path).await?;

    let x25519_pk_hex = hex::encode(identity.x25519_public.as_bytes());
    let kem_pk_hex = hex::encode(identity.kem_pk.as_bytes());

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
        auth,
        http_client: reqwest::Client::new(),
        log_buffer: logs::new_buffer(),
    };

    // Start admin UI server.
    let admin_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = admin::start_admin(args.admin_addr, admin_state).await {
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

    // Seam server accept loop.
    let mut server = Server::bind(args.seam_addr, identity)
        .await
        .map_err(|e| anyhow!("seam bind failed: {e}"))?;
    info!("seam server listening on udp://{}", args.seam_addr);

    while let Some(conn) = server.accept().await {
        let remote = conn.remote_addr().await;
        info!("seam connection from {remote}");
        let mux = SeamMux::new(conn);
        let s = state.clone();
        tokio::spawn(async move {
            if let Err(e) = tunnel::handle_client(
                mux,
                s.tunnels,
                s.tcp_ports,
                (*s.base_domain).clone(),
                s.http_port,
                s.auth,
            )
            .await
            {
                warn!("client from {remote} ended: {e:#}");
            }
        });
    }

    Ok(())
}

async fn load_or_create_identity(
    store: &SharedStore,
    store_path: &Arc<PathBuf>,
) -> Result<IdentityKeypair> {
    // Try to load all three components from the store.
    let saved = {
        let s = store.read().await;
        match (
            s.identity_x25519_hex.clone(),
            s.identity_kem_pk_hex.clone(),
            s.identity_kem_sk_hex.clone(),
        ) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    };

    if let Some((x25519_hex, kem_pk_hex, kem_sk_hex)) = saved {
        let x25519_bytes: [u8; 32] = hex::decode(&x25519_hex)
            .map_err(|_| anyhow!("invalid x25519 secret in store"))?
            .try_into()
            .map_err(|_| anyhow!("x25519 secret wrong length"))?;
        let kem_pk_bytes = hex::decode(&kem_pk_hex)
            .map_err(|_| anyhow!("invalid kem pubkey hex in store"))?;
        let kem_sk_bytes = hex::decode(&kem_sk_hex)
            .map_err(|_| anyhow!("invalid kem secret hex in store"))?;

        let x25519_secret = x25519_dalek::StaticSecret::from(x25519_bytes);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
        let kem_pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(&kem_pk_bytes)
            .map_err(|_| anyhow!("invalid kyber768 public key in store"))?;
        let kem_sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(&kem_sk_bytes)
            .map_err(|_| anyhow!("invalid kyber768 secret key in store"))?;

        info!("loaded persistent relay identity from store");
        return Ok(IdentityKeypair { x25519_secret, x25519_public, kem_pk, kem_sk });
    }

    // Generate a fresh identity and persist it.
    let identity = IdentityKeypair::generate();
    {
        let mut s = store.write().await;
        s.identity_x25519_hex = Some(hex::encode(identity.x25519_secret.to_bytes()));
        s.identity_kem_pk_hex = Some(hex::encode(identity.kem_pk.as_bytes()));
        s.identity_kem_sk_hex = Some(hex::encode(identity.kem_sk.as_bytes()));
    }
    store::save(store, store_path).await?;
    info!("generated and saved new relay identity");
    Ok(identity)
}
