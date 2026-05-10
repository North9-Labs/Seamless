use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{delete, get, put},
    Json,
};
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::cloudflare::{CfClient, CreateDnsRecord};
use crate::store::{self, CfSettings, ProxyRoute};
use crate::AppState;

const UI_HTML: &str = include_str!("admin.html");

// ── Server startup ─────────────────────────────────────────────────────────

pub async fn start_admin(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let shared = Arc::new(state);
    let app = Router::new()
        .route("/", get(serve_ui))
        // Proxy routes
        .route("/api/routes", get(list_routes).post(create_route))
        .route("/api/routes/{id}", put(update_route).delete(delete_route))
        // Seamless tunnels (read-only)
        .route("/api/tunnels", get(list_seamless_tunnels))
        // Logs + health
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
        .layer(CorsLayer::permissive())
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("admin ui listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
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
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "domain and upstream_url required"})),
        )
            .into_response();
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

// ── Seamless Tunnels ──────────────────────────────────────────────────────────

async fn list_seamless_tunnels(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let http: Vec<_> = {
        let t = s.tunnels.lock().await;
        t.keys()
            .map(|sub| {
                serde_json::json!({
                    "subdomain": sub,
                    "url": format!("http://{}.{}:{}", sub, s.base_domain, s.http_port),
                })
            })
            .collect()
    };
    let tcp: Vec<_> = {
        let p = s.tcp_ports.lock().await;
        p.iter()
            .map(|port| {
                serde_json::json!({
                    "port": port,
                    "url": format!("tcp://{}:{}", s.base_domain, port),
                })
            })
            .collect()
    };
    Json(serde_json::json!({ "http": http, "tcp": tcp }))
}

// ── Status ────────────────────────────────────────────────────────────────────

async fn get_status(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "seam_addr": s.seam_addr,
        "x25519_pubkey": s.relay_pubkeys.x25519,
        "kem_pubkey": s.relay_pubkeys.kem,
        "base_domain": s.base_domain.as_ref(),
    }))
}

// ── Logs ──────────────────────────────────────────────────────────────────────

async fn get_logs(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let buf = s.log_buffer.lock().await;
    let entries: Vec<_> = buf.iter().rev().cloned().collect();
    Json(serde_json::json!(entries))
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
        return err("CF credentials not configured").into_response();
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
        return err("CF credentials not configured").into_response();
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
        return err("CF credentials not configured").into_response();
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
        return err("CF credentials not configured").into_response();
    };
    match cf.get_tunnel_token(&id).await {
        Ok(token) => Json(serde_json::json!({ "token": token })).into_response(),
        Err(e) => err(e).into_response(),
    }
}

// ── CF Zones ──────────────────────────────────────────────────────────────────

async fn cf_list_zones(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(cf) = cf_client(&s).await else {
        return err("CF credentials not configured").into_response();
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
        return err("CF credentials not configured").into_response();
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
        return err("CF credentials not configured").into_response();
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
        return err("CF credentials not configured").into_response();
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
        return err("CF credentials not configured").into_response();
    };
    match cf.delete_dns_record(&zone_id, &record_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(e).into_response(),
    }
}
