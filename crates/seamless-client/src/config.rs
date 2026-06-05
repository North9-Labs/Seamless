use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    pub relay: Option<String>,
    pub x25519: Option<String>,
    pub kem: Option<String>,
    pub token: Option<String>,
}

fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("seamless")
        .join("config.toml")
}

pub fn load() -> ClientConfig {
    let path = config_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ClientConfig::default();
    };
    toml::from_str(&text).unwrap_or_default()
}

pub fn save(cfg: &ClientConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create config dir")?;
    }
    let text = toml::to_string_pretty(cfg).context("serialize config")?;
    std::fs::write(&path, text).context("write config")?;
    Ok(())
}

pub fn path_display() -> String {
    config_path().display().to_string()
}
