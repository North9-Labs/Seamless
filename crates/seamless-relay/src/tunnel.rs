use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use seamless_common::{read_frame, write_frame, ControlFrame, TunnelKind, PROTOCOL_VERSION};
use seam_protocol::tunnel::{SeamMux, SeamStream};
use rand::Rng;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

pub type TunnelMap = Arc<Mutex<HashMap<String, Arc<SeamMux>>>>;
pub type TcpPortSet = Arc<Mutex<HashSet<u16>>>;

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
        let mut hit = 0u8;
        for candidate in allowed.iter() {
            let cbytes = candidate.as_bytes();
            if cbytes.len() == tbytes.len() {
                hit |= cbytes.ct_eq(tbytes).unwrap_u8();
            }
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

pub async fn handle_client(
    mux: Arc<SeamMux>,
    tunnels: TunnelMap,
    tcp_ports: TcpPortSet,
    base_domain: String,
    http_port: u16,
    auth: AuthPolicy,
) -> Result<()> {
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

    match kind {
        TunnelKind::Http { subdomain } => {
            serve_http(mux, control, tunnels, base_domain, http_port, subdomain).await
        }
        TunnelKind::Tcp { port } => {
            serve_tcp(mux, control, tcp_ports, base_domain, port).await
        }
    }
}

async fn serve_http(
    mux: Arc<SeamMux>,
    mut control: SeamStream,
    tunnels: TunnelMap,
    base_domain: String,
    http_port: u16,
    subdomain: Option<String>,
) -> Result<()> {
    let sub = subdomain.unwrap_or_else(random_subdomain);
    let url = format!("http://{sub}.{base_domain}:{http_port}");

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
        t.insert(sub.clone(), mux.clone());
    }

    write_frame(&mut control, &ControlFrame::Registered { public_url: url.clone() }).await?;
    info!("registered http tunnel: {url}");

    let mut drain = [0u8; 256];
    loop {
        match control.read(&mut drain).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }

    tunnels.lock().await.remove(&sub);
    info!("deregistered http tunnel for subdomain {sub}");
    Ok(())
}

async fn serve_tcp(
    mux: Arc<SeamMux>,
    mut control: SeamStream,
    tcp_ports: TcpPortSet,
    base_domain: String,
    requested_port: u16,
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

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mux_for_listener = mux.clone();
    let listener_task = tokio::spawn(async move {
        run_tcp_listener(listener, mux_for_listener, shutdown_rx).await;
    });

    let mut drain = [0u8; 256];
    loop {
        match control.read(&mut drain).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }

    let _ = shutdown_tx.send(());
    let _ = listener_task.await;
    tcp_ports.lock().await.remove(&port);
    info!("deregistered tcp tunnel on port {port}");
    Ok(())
}

async fn bind_random_port(in_use: &TcpPortSet) -> Result<(TcpListener, u16)> {
    for _ in 0..50 {
        let port: u16 = rand::thread_rng().gen_range(10_000..60_000);
        {
            let mut set = in_use.lock().await;
            if set.contains(&port) {
                continue;
            }
            match TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await {
                Ok(l) => {
                    set.insert(port);
                    return Ok((l, port));
                }
                Err(_) => continue,
            }
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
    let n: u32 = rand::thread_rng().gen_range(0x1000_0000..0xFFFF_FFFF);
    format!("t{n:x}")
}
