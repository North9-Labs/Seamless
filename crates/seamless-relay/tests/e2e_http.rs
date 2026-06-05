//! End-to-end test: in-process relay + client + origin over a real Seam
//! connection on loopback, driven by raw TCP requests to the relay's HTTP
//! ingress. Validates the wire protocol, the Host→subdomain router, and
//! the bidirectional bytes end-to-end.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use seam_protocol::api::{Client, Server};
use seam_protocol::handshake::{pk_from_bytes, pk_to_bytes, IdentityKeypair};
use seam_protocol::tunnel::{SeamMux, SeamStream};
use seamless_common::{read_frame, write_frame, ControlFrame, TunnelKind, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

type TunnelMap = Arc<Mutex<HashMap<String, Arc<SeamMux>>>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_tunnel_round_trip() {
    let outcome = tokio::time::timeout(Duration::from_secs(20), run_test()).await;
    outcome.expect("test timed out after 20s");
}

async fn run_test() {
    // ── relay identity + server ──────────────────────────────────────────
    let relay_id = IdentityKeypair::generate();
    let relay_x25519: [u8; 32] = *relay_id.x25519_public.as_bytes();
    let relay_kem_bytes: Vec<u8> = pk_to_bytes(&relay_id.kem_pk);

    let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), relay_id)
        .await
        .expect("relay bind");
    let apex_addr = server.local_addr().expect("relay local_addr");

    let tunnels: TunnelMap = Arc::new(Mutex::new(HashMap::new()));

    // ── HTTP ingress ─────────────────────────────────────────────────────
    let ingress = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ingress bind");
    let ingress_addr = ingress.local_addr().expect("ingress local_addr");
    let ingress_tunnels = tunnels.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = ingress.accept().await else {
                break;
            };
            let tmap = ingress_tunnels.clone();
            tokio::spawn(async move {
                let _ = relay_route_http(tcp, peer, tmap).await;
            });
        }
    });

    // ── Apex accept loop + control-stream dispatcher ─────────────────────
    let accept_tunnels = tunnels.clone();
    tokio::spawn(async move {
        while let Some(conn) = server.accept().await {
            let mux = SeamMux::new(conn);
            let tmap = accept_tunnels.clone();
            tokio::spawn(async move {
                let _ = relay_handle_client(mux, tmap).await;
            });
        }
    });

    // ── origin: canned HTTP server ───────────────────────────────────────
    let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_addr = origin.local_addr().expect("origin local_addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = origin.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut junk = [0u8; 1024];
                let _ = tcp.read(&mut junk).await;
                let _ = tcp.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
                ).await;
                let _ = tcp.shutdown().await;
            });
        }
    });

    // ── client: connect, register subdomain, forward to origin ───────────
    let client_id = IdentityKeypair::generate();
    let mut client = Client::bind("127.0.0.1:0".parse().unwrap(), client_id)
        .await
        .expect("client bind");
    let kem_pk = pk_from_bytes(&relay_kem_bytes).expect("kem pk decode");

    let conn = client
        .connect(apex_addr, &relay_x25519, &kem_pk, Default::default())
        .await
        .expect("client connect");
    let mux = SeamMux::new(conn);

    let mut control = mux.open_stream().await;
    write_frame(
        &mut control,
        &ControlFrame::Register {
            version: PROTOCOL_VERSION,
            token: None,
            kind: TunnelKind::Http {
                subdomain: Some("t".to_string()),
            },
        },
    )
    .await
    .expect("register");

    match read_frame(&mut control).await.expect("register reply") {
        ControlFrame::Registered { .. } => {}
        other => panic!("unexpected register reply: {other:?}"),
    }

    // Drain control stream in the background so the task stays alive.
    tokio::spawn(async move {
        let mut buf = [0u8; 256];
        while let Ok(n) = control.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });

    let target = format!("127.0.0.1:{}", origin_addr.port());
    let mux_for_accept = mux.clone();
    tokio::spawn(async move {
        while let Some(stream) = mux_for_accept.accept_stream().await {
            let t = target.clone();
            tokio::spawn(async move {
                let _ = client_forward(stream, t).await;
            });
        }
    });

    // ── the actual request ───────────────────────────────────────────────
    // Give the relay a beat to finish inserting the subdomain.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let body = send_http_request(ingress_addr, "t.localhost").await;
    assert!(
        body.contains("hello world"),
        "expected 'hello world' in response, got: {body:?}"
    );
}

async fn send_http_request(addr: SocketAddr, host: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.expect("ingress connect");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}:{}\r\nConnection: close\r\n\r\n",
        addr.port()
    );
    tcp.write_all(req.as_bytes()).await.expect("write req");
    let mut buf = Vec::with_capacity(1024);
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf))
        .await
        .expect("read timeout");
    String::from_utf8_lossy(&buf).into_owned()
}

async fn relay_handle_client(mux: Arc<SeamMux>, tunnels: TunnelMap) -> std::io::Result<()> {
    let mut control = match mux.accept_stream().await {
        Some(s) => s,
        None => return Ok(()),
    };
    let reg = match read_frame(&mut control).await {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };
    let kind = match reg {
        ControlFrame::Register { kind, .. } => kind,
        _ => return Ok(()),
    };
    let sub = match kind {
        TunnelKind::Http { subdomain } => subdomain.unwrap_or_else(|| "auto".into()),
        TunnelKind::Tcp { .. } => return Ok(()),
    };
    tunnels.lock().await.insert(sub.clone(), mux.clone());
    let _ = write_frame(
        &mut control,
        &ControlFrame::Registered {
            public_url: format!("http://{sub}.localhost"),
        },
    )
    .await;
    // Hold control stream open.
    let mut buf = [0u8; 256];
    while let Ok(n) = control.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
    tunnels.lock().await.remove(&sub);
    Ok(())
}

async fn relay_route_http(
    mut tcp: TcpStream,
    peer: SocketAddr,
    tunnels: TunnelMap,
) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = tcp.read(&mut buf).await?;
    let head = buf[..n].to_vec();
    let host = parse_host(&head).unwrap_or_default();
    let sub = host
        .split(':')
        .next()
        .and_then(|h| h.strip_suffix(".localhost"))
        .unwrap_or("")
        .to_string();

    let mux_opt = tunnels.lock().await.get(&sub).cloned();
    let Some(mux) = mux_opt else {
        let _ = tcp
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Ok(());
    };

    let mut stream = mux.open_stream().await;
    write_frame(
        &mut stream,
        &ControlFrame::NewConn {
            peer_addr: peer.to_string(),
        },
    )
    .await
    .ok();
    stream.write_all(&head).await.ok();
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
    Ok(())
}

async fn client_forward(mut apex: SeamStream, target: String) -> std::io::Result<()> {
    match read_frame(&mut apex).await {
        Ok(ControlFrame::NewConn { .. }) => {}
        _ => return Ok(()),
    }
    let mut local = TcpStream::connect(&target).await?;
    let _ = tokio::io::copy_bidirectional(&mut local, &mut apex).await;
    Ok(())
}

fn parse_host(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    for line in s.split("\r\n") {
        for prefix in ["Host:", "host:", "HOST:"] {
            if let Some(rest) = line.strip_prefix(prefix) {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}
