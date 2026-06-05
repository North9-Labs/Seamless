use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use subtle::ConstantTimeEq;

use axum::{
    Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json,
};
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::cloudflare::{CfClient, CreateDnsRecord};
use crate::store::{self, unix_now, CfSettings, ProxyRoute};
use crate::AppState;

const UI_HTML: &str = include_str!("admin.html");

// ── Server startup ─────────────────────────────────────────────────────────

/// Configuration for optional TLS/mTLS on the admin port.
pub struct AdminTlsConfig {
    pub acceptor: tokio_rustls::TlsAcceptor,
    /// True when mutual TLS is enabled (client cert required).
    pub mtls: bool,
}

pub async fn start_admin(
    addr: SocketAddr,
    state: AppState,
    tls: Option<AdminTlsConfig>,
) -> anyhow::Result<()> {
    let shared = Arc::new(state);
    let app = Router::new()
        .route("/", get(serve_ui))
        // Health / readiness / metrics (public — used by load balancers)
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/metrics", get(metrics_handler))
        // Proxy routes
        .route("/api/routes", get(list_routes).post(create_route))
        .route("/api/routes/{id}", put(update_route).delete(delete_route))
        // Seamless tunnels — read-only list (protected by admin token)
        .route("/api/tunnels", get(list_seamless_tunnels))
        // Single tunnel details by ID
        .route("/api/tunnels/{id}", get(get_seamless_tunnel))
        // Stats history ring buffer
        .route("/api/stats/history", get(stats_history_handler))
        // Seamless tunnels — admin management (protected by Bearer token)
        .route("/admin/tunnels/disconnect", post(admin_bulk_disconnect))
        .route("/admin/tunnels/{id}", delete(admin_disconnect_tunnel))
        .route("/admin/tunnels/{id}/stats", get(admin_tunnel_stats))
        .route("/admin/tunnels/{id}/pause", post(admin_pause_tunnel))
        .route("/admin/tunnels/{id}/resume", post(admin_resume_tunnel))
        // Logs + route health (logs protected by admin token)
        .route("/api/logs", get(get_logs))
        .route("/api/routes/health", get(health_routes))
        // Relay status
        .route("/api/status", get(get_status))
        // Settings (CF credentials)
        .route("/api/settings", get(get_settings).put(save_settings))
        // CF Tunnels
        .route("/api/cf/tunnels", get(cf_list_tunnels).post(cf_create_tunnel))
        .route("/api/cf/tunnels/{id}", delete(cf_delete_tunnel))
        .route("/api/cf/tunnels/{id}/token", get(cf_tunnel_token))
        // CF Zones
        .route("/api/cf/zones", get(cf_list_zones))
        // CF DNS
        .route("/api/cf/dns/{zone_id}", get(cf_list_dns).post(cf_create_dns))
        .route(
            "/api/cf/dns/{zone_id}/{record_id}",
            put(cf_update_dns).delete(cf_delete_dns),
        )
        .layer(middleware::from_fn_with_state(shared.clone(), require_admin_ip))
        .layer(CorsLayer::permissive())
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    if let Some(tls_cfg) = tls {
        let scheme = if tls_cfg.mtls { "https (mTLS)" } else { "https (TLS)" };
        info!("admin ui listening on {scheme} https://{addr}");
        if tls_cfg.mtls {
            info!("admin mTLS: client certificates required — only CA-signed clients admitted");
        }
        let acceptor = tls_cfg.acceptor;
        // Serve connections one at a time via the TLS acceptor.
        let make_svc = app.into_make_service_with_connect_info::<SocketAddr>();
        serve_tls(listener, acceptor, make_svc).await?;
    } else {
        info!("admin ui listening on http://{addr}");
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    }
    Ok(())
}

/// Accept TLS connections and hand them to axum.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    mut make_svc: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use tower::Service;

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => { tracing::warn!("admin TLS accept: {e}"); continue; }
        };
        let acceptor = acceptor.clone();
        let svc = match make_svc.call(peer_addr).await {
            Ok(s) => s,
            Err(e) => { tracing::warn!("admin make_svc: {e:?}"); continue; }
        };
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("admin TLS handshake from {peer_addr}: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let builder = AutoBuilder::new(TokioExecutor::new());
            if let Err(e) = builder
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req| {
                        let mut svc = svc.clone();
                        async move { svc.call(req).await }
                    }),
                )
                .await
            {
                tracing::debug!("admin TLS connection from {peer_addr} closed: {e}");
            }
        });
    }
}

// ── IP allowlist middleware ───────────────────────────────────────────────────

async fn require_admin_ip(
    State(s): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !crate::ip_in_cidr(addr.ip(), &s.admin_cidrs) {
        return (StatusCode::FORBIDDEN, "Admin access denied from your IP\n").into_response();
    }
    next.run(req).await
}

// ── UI ──────────────────────────────────────────────────────────────────────

async fn serve_ui() -> Html<&'static str> {
    Html(UI_HTML)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn err(msg: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": msg.to_string() })),
    )
}

fn bad_request(msg: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg.to_string() })),
    )
}

fn credentials_required() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "error": "credentials not configured — set CF API token and account ID in Settings" })),
    )
}

fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not found" })),
    )
}

async fn cf_client(s: &AppState) -> Option<CfClient> {
    let guard = s.store.read().await;
    let cf = guard.cf.as_ref()?;
    if cf.api_token.is_empty() || cf.account_id.is_empty() {
        return None;
    }
    Some(CfClient::new(&cf.api_token, &cf.account_id, s.http_client.clone()))
}

// ── Proxy Routes ──────────────────────────────────────────────────────────────

async fn list_routes(State(s): State<Arc<AppState>>) -> Json<Vec<ProxyRoute>> {
    let store = s.store.read().await;
    Json(store.routes.clone())
}

#[derive(Deserialize)]
struct RouteReq {
    domain: String,
    upstream_url: String,
    #[serde(default = "crate::store::default_true_pub")]
    enabled: bool,
}

async fn create_route(
    State(s): State<Arc<AppState>>,
    Json(req): Json<RouteReq>,
) -> impl IntoResponse {
    let domain = req.domain.trim().to_lowercase();
    let upstream_url = req.upstream_url.trim().to_string();
    if domain.is_empty() || upstream_url.is_empty() {
        return bad_request("domain and upstream_url required").into_response();
    }
    let route = ProxyRoute {
        id: uuid::Uuid::new_v4().to_string(),
        domain: domain.clone(),
        upstream_url,
        enabled: req.enabled,
        created_at: store::unix_now(),
    };
    {
        let mut store = s.store.write().await;
        if store.routes.iter().any(|r| r.domain == domain) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "domain already exists"})),
            )
                .into_response();
        }
        store.routes.push(route.clone());
    }
    store::save(&s.store, &s.store_path).await.ok();
    (StatusCode::CREATED, Json(route)).into_response()
}

async fn update_route(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<RouteReq>,
) -> impl IntoResponse {
    let domain = req.domain.trim().to_lowercase();
    let upstream_url = req.upstream_url.trim().to_string();
    let updated = {
        let mut store = s.store.write().await;
        if let Some(r) = store.routes.iter_mut().find(|r| r.id == id) {
            r.domain = domain;
            r.upstream_url = upstream_url;
            r.enabled = req.enabled;
            Some(r.clone())
        } else {
            None
        }
    };
    match updated {
        Some(r) => {
            store::save(&s.store, &s.store_path).await.ok();
            Json(r).into_response()
        }
        None => not_found().into_response(),
    }
}

async fn delete_route(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> StatusCode {
    let deleted = {
        let mut store = s.store.write().await;
        let before = store.routes.len();
        store.routes.retain(|r| r.id != id);
        store.routes.len() < before
    };
    if deleted {
        store::save(&s.store, &s.store_path).await.ok();
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// ── Seamless Tunnels (read-only list) ─────────────────────────────────────────

async fn list_seamless_tunnels(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let t = s.tunnels.lock().await;
    let now = unix_now();
    let (http, tcp): (Vec<_>, Vec<_>) = t.values().partition(|e| !e.subdomain.starts_with("tcp:"));
    let http: Vec<_> = http
        .iter()
        .map(|entry| {
            // Show https:// URL when the relay has TLS configured.
            let url = if let Some(port) = s.https_port {
                if port == 443 {
                    format!("https://{}.{}", entry.subdomain, s.base_domain)
                } else {
                    format!("https://{}.{}:{}", entry.subdomain, s.base_domain, port)
                }
            } else if s.http_port == 80 {
                format!("http://{}.{}", entry.subdomain, s.base_domain)
            } else {
                format!("http://{}.{}:{}", entry.subdomain, s.base_domain, s.http_port)
            };
            serde_json::json!({
                "subdomain": entry.subdomain,
                "url": url,
                "paused": entry.paused.load(Ordering::Relaxed),
                "connected_at": entry.connected_at,
                "duration_secs": now - entry.connected_at,
                "client_ip": entry.client_ip,
                "bytes_in": entry.bytes_in.load(Ordering::Relaxed),
                "bytes_out": entry.bytes_out.load(Ordering::Relaxed),
            })
        })
        .collect();
    let tcp: Vec<_> = tcp
        .iter()
        .map(|entry| {
            serde_json::json!({
                "key": entry.subdomain,
                "url": format!("tcp://{}:{}", s.base_domain, entry.subdomain.trim_start_matches("tcp:")),
                "connected_at": entry.connected_at,
                "duration_secs": now - entry.connected_at,
                "client_ip": entry.client_ip,
                "bytes_in": entry.bytes_in.load(Ordering::Relaxed),
                "bytes_out": entry.bytes_out.load(Ordering::Relaxed),
            })
        })
        .collect();
    Json(serde_json::json!({ "http": http, "tcp": tcp })).into_response()
}

// ── Single tunnel details (read-only) ────────────────────────────────────────

/// `GET /api/tunnels/:id` — return details for a single tunnel by subdomain key.
/// Returns the same fields as the list endpoint for the matching tunnel, plus
/// `tunnel_type` ("http" | "tcp") for easier programmatic use.
async fn get_seamless_tunnel(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let entry = {
        let t = s.tunnels.lock().await;
        t.get(&id).cloned()
    };
    let Some(entry) = entry else {
        return not_found().into_response();
    };
    let now = unix_now();
    let is_tcp = entry.subdomain.starts_with("tcp:");
    let json = if is_tcp {
        let port = entry.subdomain.trim_start_matches("tcp:");
        serde_json::json!({
            "id": entry.subdomain,
            "tunnel_type": "tcp",
            "url": format!("tcp://{}:{}", s.base_domain.as_ref(), port),
            "connected_at": entry.connected_at,
            "uptime_secs": now - entry.connected_at,
            "client_ip": entry.client_ip,
            "bytes_in": entry.bytes_in.load(Ordering::Relaxed),
            "bytes_out": entry.bytes_out.load(Ordering::Relaxed),
            "paused": entry.paused.load(Ordering::Relaxed),
        })
    } else {
        let url = if let Some(port) = s.https_port {
            if port == 443 {
                format!("https://{}.{}", entry.subdomain, s.base_domain)
            } else {
                format!("https://{}.{}:{}", entry.subdomain, s.base_domain, port)
            }
        } else if s.http_port == 80 {
            format!("http://{}.{}", entry.subdomain, s.base_domain)
        } else {
            format!("http://{}.{}:{}", entry.subdomain, s.base_domain, s.http_port)
        };
        serde_json::json!({
            "id": entry.subdomain,
            "tunnel_type": "http",
            "subdomain": entry.subdomain,
            "url": url,
            "connected_at": entry.connected_at,
            "uptime_secs": now - entry.connected_at,
            "client_ip": entry.client_ip,
            "bytes_in": entry.bytes_in.load(Ordering::Relaxed),
            "bytes_out": entry.bytes_out.load(Ordering::Relaxed),
            "paused": entry.paused.load(Ordering::Relaxed),
        })
    };
    Json(json).into_response()
}

// ── Admin tunnel management (protected by Bearer token) ───────────────────────

/// Returns `Some(unauthorized_response)` if the admin token check fails.
/// Comparison is constant-time to prevent timing-based token enumeration.
fn check_admin_auth(
    headers: &HeaderMap,
    expected: &Option<String>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let Some(tok) = expected else {
        return None; // No token configured — endpoint is open.
    };
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let ok = match provided {
        Some(t) => t.as_bytes().ct_eq(tok.as_bytes()).into(),
        None => false,
    };
    if ok {
        None
    } else {
        Some((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid or missing admin token",
                "hint": "Authorization: Bearer <token>"
            })),
        ))
    }
}

/// `DELETE /admin/tunnels/:id` — forcibly disconnect a tunnel.
async fn admin_disconnect_tunnel(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let entry = {
        let t = s.tunnels.lock().await;
        t.get(&id).cloned()
    };
    let Some(entry) = entry else {
        return not_found().into_response();
    };

    // Emit audit log event and webhook before disconnecting.
    let now = unix_now();
    let duration_secs = now - entry.connected_at;
    tracing::info!(
        event = "tunnel.admin_disconnect",
        subdomain = %entry.subdomain,
        client_ip = %entry.client_ip,
        duration_secs = duration_secs,
        "admin forcibly disconnected tunnel '{}' from {} ({}s)",
        entry.subdomain, entry.client_ip, duration_secs
    );
    // Fire webhook non-blockingly.
    if let Some(ref url) = *s.webhook_url {
        let webhook = crate::tunnel::WebhookCtx {
            url: Some(std::sync::Arc::new(url.clone())),
            client: s.http_client.clone(),
        };
        webhook.fire(serde_json::json!({
            "event": "tunnel.admin_disconnect",
            "subdomain": entry.subdomain,
            "client_ip": entry.client_ip,
            "duration_secs": duration_secs,
        }));
    }

    // Send disconnect signal; the tunnel task cleans itself up.
    let mut tx_guard = entry.disconnect_tx.lock().await;
    if let Some(tx) = tx_guard.take() {
        let _ = tx.send(());
        (StatusCode::NO_CONTENT, Json(serde_json::Value::Null)).into_response()
    } else {
        // Already disconnecting.
        (StatusCode::NO_CONTENT, Json(serde_json::Value::Null)).into_response()
    }
}

/// `GET /admin/tunnels/:id/stats` — bytes in/out, duration, client IP, subdomain.
async fn admin_tunnel_stats(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let entry = {
        let t = s.tunnels.lock().await;
        t.get(&id).cloned()
    };
    let Some(entry) = entry else {
        return not_found().into_response();
    };
    let now = unix_now();
    Json(serde_json::json!({
        "subdomain": entry.subdomain,
        "client_ip": entry.client_ip,
        "connected_at": entry.connected_at,
        "duration_secs": now - entry.connected_at,
        "bytes_in": entry.bytes_in.load(Ordering::Relaxed),
        "bytes_out": entry.bytes_out.load(Ordering::Relaxed),
        "paused": entry.paused.load(Ordering::Relaxed),
    }))
    .into_response()
}

/// `POST /admin/tunnels/:id/pause` — block new connections without disconnecting.
async fn admin_pause_tunnel(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let entry = {
        let t = s.tunnels.lock().await;
        t.get(&id).cloned()
    };
    let Some(entry) = entry else {
        return not_found().into_response();
    };
    entry.paused.store(true, Ordering::Relaxed);
    tracing::info!("admin paused tunnel {id}");
    (StatusCode::NO_CONTENT, Json(serde_json::Value::Null)).into_response()
}

/// `POST /admin/tunnels/:id/resume` — lift a pause.
async fn admin_resume_tunnel(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let entry = {
        let t = s.tunnels.lock().await;
        t.get(&id).cloned()
    };
    let Some(entry) = entry else {
        return not_found().into_response();
    };
    entry.paused.store(false, Ordering::Relaxed);
    tracing::info!("admin resumed tunnel {id}");
    (StatusCode::NO_CONTENT, Json(serde_json::Value::Null)).into_response()
}

/// `GET /api/stats/history` — return the rolling 60-entry stats ring buffer.
async fn stats_history_handler(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let history = s.stats_history.snapshot().await;
    Json(serde_json::json!({ "history": history })).into_response()
}

/// `POST /admin/tunnels/disconnect` — bulk-disconnect all tunnels from a given IP.
///
/// Body: `{"client_ip": "1.2.3.4"}`
///
/// Useful for rapid incident response: one call evicts every tunnel belonging
/// to a compromised or misbehaving client IP.
async fn admin_bulk_disconnect(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BulkDisconnectReq>,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }

    let target_ip = req.client_ip.trim().to_string();
    if target_ip.is_empty() {
        return bad_request("client_ip is required").into_response();
    }

    // Collect matching entries while holding the lock, then disconnect each.
    let matching: Vec<Arc<crate::tunnel::TunnelEntry>> = {
        let t = s.tunnels.lock().await;
        t.values()
            .filter(|e| e.client_ip == target_ip)
            .cloned()
            .collect()
    };

    if matching.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("no active tunnels found for IP {target_ip}"),
                "disconnected": 0_u32,
            })),
        )
            .into_response();
    }

    let now = unix_now();
    let count = matching.len();
    for entry in &matching {
        let duration_secs = now - entry.connected_at;
        tracing::info!(
            event = "tunnel.admin_bulk_disconnect",
            subdomain = %entry.subdomain,
            client_ip = %entry.client_ip,
            duration_secs = duration_secs,
            "admin bulk-disconnected tunnel '{}' from {} ({}s)",
            entry.subdomain, entry.client_ip, duration_secs
        );
        // Fire webhook for each evicted tunnel.
        if let Some(ref url) = *s.webhook_url {
            let webhook = crate::tunnel::WebhookCtx {
                url: Some(std::sync::Arc::new(url.clone())),
                client: s.http_client.clone(),
            };
            webhook.fire(serde_json::json!({
                "event": "tunnel.admin_bulk_disconnect",
                "subdomain": entry.subdomain,
                "client_ip": entry.client_ip,
                "duration_secs": duration_secs,
            }));
        }
        let mut tx_guard = entry.disconnect_tx.lock().await;
        if let Some(tx) = tx_guard.take() {
            let _ = tx.send(());
        }
    }

    tracing::info!(
        event = "tunnel.bulk_disconnect_complete",
        client_ip = %target_ip,
        count = count,
        "admin bulk-disconnect: evicted {count} tunnel(s) from {target_ip}"
    );

    Json(serde_json::json!({
        "disconnected": count,
        "client_ip": target_ip,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct BulkDisconnectReq {
    client_ip: String,
}

// ── Health / Ready / Metrics (public, used by load balancers) ─────────────────

async fn health_check(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let tunnels = s.tunnels.lock().await.len();
    let uptime_secs = s.start_time.elapsed().as_secs();
    Json(serde_json::json!({
        "status": "ok",
        "tunnels": tunnels,
        "uptime_secs": uptime_secs,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn ready_check(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // The relay is ready as long as the tunnels map is accessible.
    let tunnels = s.tunnels.lock().await.len();
    let uptime_secs = s.start_time.elapsed().as_secs();
    Json(serde_json::json!({
        "status": "ok",
        "tunnels": tunnels,
        "uptime_secs": uptime_secs,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn metrics_handler(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let tunnels_active = s.tunnels.lock().await.len() as u64;
    let bytes_in = s.metrics.bytes_in.load(Ordering::Relaxed);
    let bytes_out = s.metrics.bytes_out.load(Ordering::Relaxed);
    let connections_total = s.metrics.connections_total.load(Ordering::Relaxed);
    let handshake_avg = s.metrics.handshake_avg_ms();
    let auth_failures = s.metrics.auth_failures_total.load(Ordering::Relaxed);
    let rate_limit_hits = s.metrics.rate_limit_hits_total.load(Ordering::Relaxed);
    let tunnel_cap_rejections = s.metrics.tunnel_cap_rejections_total.load(Ordering::Relaxed);
    let subdomain_invalid = s.metrics.subdomain_invalid_total.load(Ordering::Relaxed);
    let tunnel_per_ip_rejections = s.metrics.tunnel_per_ip_rejections_total.load(Ordering::Relaxed);

    let uptime_secs = s.start_time.elapsed().as_secs();
    let version = env!("CARGO_PKG_VERSION");
    let body = format!(
        "# HELP seamless_info Relay version info\n\
         # TYPE seamless_info gauge\n\
         seamless_info{{version=\"{version}\"}} 1\n\
         # HELP seamless_uptime_seconds Seconds since relay start\n\
         # TYPE seamless_uptime_seconds counter\n\
         seamless_uptime_seconds {uptime_secs}\n\
         # HELP seamless_tunnels_active Currently connected tunnel count\n\
         # TYPE seamless_tunnels_active gauge\n\
         seamless_tunnels_active {tunnels_active}\n\
         # HELP seamless_bytes_in_total Bytes received from public internet\n\
         # TYPE seamless_bytes_in_total counter\n\
         seamless_bytes_in_total {bytes_in}\n\
         # HELP seamless_bytes_out_total Bytes sent to public internet\n\
         # TYPE seamless_bytes_out_total counter\n\
         seamless_bytes_out_total {bytes_out}\n\
         # HELP seamless_connections_total Total tunnel registrations since start\n\
         # TYPE seamless_connections_total counter\n\
         seamless_connections_total {connections_total}\n\
         # HELP seamless_handshake_duration_ms_avg Average Seam handshake duration\n\
         # TYPE seamless_handshake_duration_ms_avg gauge\n\
         seamless_handshake_duration_ms_avg {handshake_avg:.1}\n\
         # HELP seamless_auth_failures_total Total authentication failures (missing or invalid token)\n\
         # TYPE seamless_auth_failures_total counter\n\
         seamless_auth_failures_total {auth_failures}\n\
         # HELP seamless_rate_limit_hits_total Total connections rejected by the per-IP rate limiter\n\
         # TYPE seamless_rate_limit_hits_total counter\n\
         seamless_rate_limit_hits_total {rate_limit_hits}\n\
         # HELP seamless_tunnel_cap_rejections_total Total connections rejected due to global tunnel cap\n\
         # TYPE seamless_tunnel_cap_rejections_total counter\n\
         seamless_tunnel_cap_rejections_total {tunnel_cap_rejections}\n\
         # HELP seamless_subdomain_invalid_total Total subdomain validation failures\n\
         # TYPE seamless_subdomain_invalid_total counter\n\
         seamless_subdomain_invalid_total {subdomain_invalid}\n\
         # HELP seamless_tunnel_per_ip_rejections_total Total connections rejected due to per-IP tunnel limit\n\
         # TYPE seamless_tunnel_per_ip_rejections_total counter\n\
         seamless_tunnel_per_ip_rejections_total {tunnel_per_ip_rejections}\n"
    );

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

// ── Status ────────────────────────────────────────────────────────────────────

async fn get_status(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let auth_file = s.auth_file.as_ref().as_ref().map(|p| p.display().to_string());
    let config_file = s.config_file.as_ref().as_ref().map(|p| p.display().to_string());
    let uptime_secs = s.start_time.elapsed().as_secs();
    Json(serde_json::json!({
        "seam_addr": s.seam_addr,
        "x25519_pubkey": s.relay_pubkeys.x25519,
        "kem_pubkey": s.relay_pubkeys.kem,
        "base_domain": s.base_domain.as_ref(),
        "cipher": s.cipher.as_ref(),
        "https": s.https_port.is_some(),
        "auth_enabled": auth_file.is_some(),
        "auth_file": auth_file,
        "config_file": config_file,
        "uptime_secs": uptime_secs,
        "version": env!("CARGO_PKG_VERSION"),
        "max_tunnels": s.max_tunnels,
        "max_tunnels_per_ip": s.max_tunnels_per_ip,
    }))
}

// ── Logs ──────────────────────────────────────────────────────────────────────

async fn get_logs(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(deny) = check_admin_auth(&headers, &s.admin_token) {
        return deny.into_response();
    }
    let buf = s.log_buffer.lock().await;
    let entries: Vec<_> = buf.iter().rev().cloned().collect();
    Json(serde_json::json!(entries)).into_response()
}

// ── Health ────────────────────────────────────────────────────────────────────

async fn health_routes(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use std::time::Duration;

    let routes = {
        let store = s.store.read().await;
        store.routes.clone()
    };

    let mut tasks = Vec::new();
    for r in routes {
        let url = r.upstream_url.clone();
        let id = r.id.clone();
        tasks.push(tokio::spawn(async move {
            let addr = match crate::ingress::parse_upstream_addr(&url) {
                Ok(a) => a,
                Err(_) => return (id, "unknown"),
            };
            let ok = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            .is_ok_and(|r| r.is_ok());
            (id, if ok { "up" } else { "down" })
        }));
    }

    let mut map = serde_json::Map::new();
    for task in tasks {
        if let Ok((id, status)) = task.await {
            map.insert(id, serde_json::json!(status));
        }
    }
    Json(serde_json::Value::Object(map))
}

// ── Settings ──────────────────────────────────────────────────────────────────

async fn get_settings(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let store = s.store.read().await;
    let cf = store.cf.clone().unwrap_or_default();
    // Mask the token — show only last 4 chars
    let masked = if cf.api_token.len() > 4 {
        format!("…{}", &cf.api_token[cf.api_token.len() - 4..])
    } else if cf.api_token.is_empty() {
        String::new()
    } else {
        "…".into()
    };
    Json(serde_json::json!({
        "cf_api_token_masked": masked,
        "cf_api_token_set": !cf.api_token.is_empty(),
        "cf_account_id": cf.account_id,
    }))
}

#[derive(Deserialize)]
struct SaveSettingsReq {
    cf_api_token: Option<String>,
    cf_account_id: String,
}

async fn save_settings(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SaveSettingsReq>,
) -> impl IntoResponse {
    let mut store = s.store.write().await;
    let existing_token = store
        .cf
        .as_ref()
        .map(|c| c.api_token.clone())
        .unwrap_or_default();

    let token = match req.cf_api_token {
        Some(t) if !t.is_empty() && !t.starts_with('…') => t,
        _ => existing_token,
    };

    store.cf = Some(CfSettings {
        api_token: token,
        account_id: req.cf_account_id.trim().to_string(),
    });
    drop(store);
    store::save(&s.store, &s.store_path).await.ok();
    StatusCode::NO_CONTENT
}

// ── CF Tunnels ────────────────────────────────────────────────────────────────

async fn cf_list_tunnels(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.list_tunnels().await {
        Ok(tunnels) => Json(tunnels).into_response(),
        Err(e) => err(e).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateTunnelReq {
    name: String,
}

async fn cf_create_tunnel(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CreateTunnelReq>,
) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.create_tunnel(req.name.trim()).await {
        Ok(t) => (StatusCode::CREATED, Json(t)).into_response(),
        Err(e) => err(e).into_response(),
    }
}

async fn cf_delete_tunnel(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.delete_tunnel(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(e).into_response(),
    }
}

async fn cf_tunnel_token(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.get_tunnel_token(&id).await {
        Ok(token) => Json(serde_json::json!({ "token": token })).into_response(),
        Err(e) => err(e).into_response(),
    }
}

// ── CF Zones ──────────────────────────────────────────────────────────────────

async fn cf_list_zones(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.list_zones().await {
        Ok(zones) => Json(zones).into_response(),
        Err(e) => err(e).into_response(),
    }
}

// ── CF DNS ────────────────────────────────────────────────────────────────────

async fn cf_list_dns(
    State(s): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.list_dns_records(&zone_id).await {
        Ok(records) => Json(records).into_response(),
        Err(e) => err(e).into_response(),
    }
}

async fn cf_create_dns(
    State(s): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
    Json(req): Json<CreateDnsRecord>,
) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.create_dns_record(&zone_id, &req).await {
        Ok(r) => (StatusCode::CREATED, Json(r)).into_response(),
        Err(e) => err(e).into_response(),
    }
}

async fn cf_update_dns(
    State(s): State<Arc<AppState>>,
    Path((zone_id, record_id)): Path<(String, String)>,
    Json(req): Json<CreateDnsRecord>,
) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.update_dns_record(&zone_id, &record_id, &req).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => err(e).into_response(),
    }
}

async fn cf_delete_dns(
    State(s): State<Arc<AppState>>,
    Path((zone_id, record_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return credentials_required().into_response();
    };
    match cf.delete_dns_record(&zone_id, &record_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(e).into_response(),
    }
}
