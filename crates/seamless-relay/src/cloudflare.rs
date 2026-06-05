use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const CF_API: &str = "https://api.cloudflare.com/client/v4";

pub struct CfClient {
    token: String,
    pub account_id: String,
    client: Client,
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfZone {
    pub id: String,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfTunnel {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub deleted_at: Option<Value>,
    #[serde(default)]
    pub connections: Vec<CfTunnelConn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfTunnelConn {
    #[serde(default)]
    pub colo_name: String,
    pub is_pending_reconnect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfDnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub proxied: bool,
    pub ttl: u32,
    pub modified_on: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub proxied: bool,
    pub ttl: u32,
}

// ── Internal response envelope ────────────────────────────────────────────────

#[derive(Deserialize)]
struct CfResp<T> {
    result: Option<T>,
    success: bool,
    errors: Vec<CfErr>,
}

#[derive(Deserialize)]
struct CfErr {
    code: u32,
    message: String,
}

impl<T> CfResp<T> {
    fn into_result(self) -> Result<T> {
        if !self.success {
            let msg = self
                .errors
                .first()
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_else(|| "unknown CF API error".into());
            return Err(anyhow!(msg));
        }
        self.result
            .ok_or_else(|| anyhow!("CF API returned null result"))
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

impl CfClient {
    pub fn new(token: impl Into<String>, account_id: impl Into<String>, client: Client) -> Self {
        Self {
            token: token.into(),
            account_id: account_id.into(),
            client,
        }
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let resp = self
            .client
            .get(format!("{CF_API}{path}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("CF GET failed")?;
        resp.json::<CfResp<T>>()
            .await
            .context("CF response parse")?
            .into_result()
    }

    async fn post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .client
            .post(format!("{CF_API}{path}"))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .context("CF POST failed")?;
        resp.json::<CfResp<T>>()
            .await
            .context("CF response parse")?
            .into_result()
    }

    async fn put<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .client
            .put(format!("{CF_API}{path}"))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .context("CF PUT failed")?;
        resp.json::<CfResp<T>>()
            .await
            .context("CF response parse")?
            .into_result()
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{CF_API}{path}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("CF DELETE failed")?;
        if resp.status().is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        Err(anyhow!("CF API error: {text}"))
    }

    // ── Zones ─────────────────────────────────────────────────────────────────

    pub async fn list_zones(&self) -> Result<Vec<CfZone>> {
        self.get("/zones?per_page=50&status=active").await
    }

    // ── Tunnels ───────────────────────────────────────────────────────────────

    pub async fn list_tunnels(&self) -> Result<Vec<CfTunnel>> {
        self.get(&format!(
            "/accounts/{}/cfd_tunnel?per_page=50&is_deleted=false",
            self.account_id
        ))
        .await
    }

    pub async fn create_tunnel(&self, name: &str) -> Result<CfTunnel> {
        let secret = {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill(&mut bytes);
            STANDARD.encode(bytes)
        };
        self.post(
            &format!("/accounts/{}/cfd_tunnel", self.account_id),
            &serde_json::json!({ "name": name, "tunnel_secret": secret }),
        )
        .await
    }

    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<()> {
        self.delete(&format!(
            "/accounts/{}/cfd_tunnel/{}",
            self.account_id, tunnel_id
        ))
        .await
    }

    pub async fn get_tunnel_token(&self, tunnel_id: &str) -> Result<String> {
        self.get(&format!(
            "/accounts/{}/cfd_tunnel/{}/token",
            self.account_id, tunnel_id
        ))
        .await
    }

    // ── DNS ───────────────────────────────────────────────────────────────────

    pub async fn list_dns_records(&self, zone_id: &str) -> Result<Vec<CfDnsRecord>> {
        self.get(&format!(
            "/zones/{zone_id}/dns_records?per_page=100&order=name"
        ))
        .await
    }

    pub async fn create_dns_record(
        &self,
        zone_id: &str,
        req: &CreateDnsRecord,
    ) -> Result<CfDnsRecord> {
        self.post(&format!("/zones/{zone_id}/dns_records"), req)
            .await
    }

    pub async fn update_dns_record(
        &self,
        zone_id: &str,
        record_id: &str,
        req: &CreateDnsRecord,
    ) -> Result<CfDnsRecord> {
        self.put(&format!("/zones/{zone_id}/dns_records/{record_id}"), req)
            .await
    }

    pub async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        self.delete(&format!("/zones/{zone_id}/dns_records/{record_id}"))
            .await
    }
}
