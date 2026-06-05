// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! Client configuration — loaded from a TOML file (either the default
//! `~/.config/seamless/config.toml` or a path supplied via `--config`).
//!
//! # Field precedence (highest to lowest)
//! 1. CLI flags (e.g. `--relay`, `--subdomain`)
//! 2. Values from the `--config` file (or the default config file)
//! 3. Zero / absent defaults

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Full set of values that can be stored in a client config file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Relay UDP address, e.g. `relay.example.com:4433`.
    pub relay: Option<String>,
    /// Relay X25519 static public key, hex-encoded.
    pub x25519: Option<String>,
    /// Relay ML-KEM-768 public key, hex-encoded.
    pub kem: Option<String>,
    /// Enrollment / auth token.
    pub token: Option<String>,
    /// Local service to forward to, e.g. `localhost:3000`.
    /// Only used when the subcommand is implicit (future work) — CLI subcommand takes precedence.
    pub local: Option<String>,
    /// Preferred subdomain to request (HTTP tunnels only).
    pub subdomain: Option<String>,
    /// Whether to verify the relay's TLS certificate (default: true).
    #[serde(default = "default_true")]
    pub tls_verify: bool,
}

fn default_true() -> bool {
    true
}

/// Return the default config file path: `~/.config/seamless/config.toml`.
pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("seamless")
        .join("config.toml")
}

/// Load a config from `path` (or the default path if `None`).
/// Silently returns a default `ClientConfig` if the file does not exist.
pub fn load_from(path: Option<&PathBuf>) -> ClientConfig {
    let resolved = path.cloned().unwrap_or_else(default_config_path);
    let Ok(text) = std::fs::read_to_string(&resolved) else {
        return ClientConfig::default();
    };
    match toml::from_str(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!(
                "warning: config file malformed, ignoring ({e})\n  path: {}",
                resolved.display()
            );
            ClientConfig::default()
        }
    }
}

/// Load config from the default path (kept for backward-compat with `config init`/`show`).
pub fn load() -> ClientConfig {
    load_from(None)
}

/// Save config to the default path (atomic: write to tmp then rename).
pub fn save(cfg: &ClientConfig) -> Result<()> {
    let path = default_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create config dir")?;
    }
    let text = toml::to_string_pretty(cfg).context("serialize config")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, &text).context("write config tmp")?;
    std::fs::rename(&tmp, &path).context("atomic rename config")?;
    Ok(())
}

pub fn path_display() -> String {
    default_config_path().display().to_string()
}
