use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

fn default_true() -> bool {
    true
}

pub fn default_true_pub() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRoute {
    pub id: String,
    pub domain: String,
    pub upstream_url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CfSettings {
    pub api_token: String,
    pub account_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub routes: Vec<ProxyRoute>,
    pub cf: Option<CfSettings>,
    /// Compact serialised identity (IdentityKeypair::to_bytes(), hex-encoded). v0.2+
    pub identity_hex: Option<String>,
    /// Legacy fields — kept for JSON forward-compat; ignored on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_x25519_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_kem_pk_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_kem_sk_hex: Option<String>,
}

pub type SharedStore = Arc<RwLock<Store>>;

pub async fn load(path: &PathBuf) -> anyhow::Result<SharedStore> {
    if path.exists() {
        let text = tokio::fs::read_to_string(path).await?;
        let store: Store = serde_json::from_str(&text)?;
        Ok(Arc::new(RwLock::new(store)))
    } else {
        Ok(Arc::new(RwLock::new(Store::default())))
    }
}

pub async fn save(store: &SharedStore, path: &PathBuf) -> anyhow::Result<()> {
    let guard = store.read().await;
    let text = serde_json::to_string_pretty(&*guard)?;
    drop(guard);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    tokio::fs::write(path, text).await?;
    Ok(())
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
