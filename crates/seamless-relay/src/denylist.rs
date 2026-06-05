// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! IP CIDR deny list — blocks connection attempts from known-bad address ranges.
//!
//! Checked before rate limiting for every inbound Seam connection.
//! Reloaded on SIGHUP without a restart.
//!
//! File format: one CIDR per line (`10.0.0.0/8`).
//! Lines beginning with `#` and blank lines are ignored.
//! Both IPv4 (`10.0.0.0/8`) and IPv4-mapped IPv6 (`::ffff:10.0.0.0/104`) are
//! handled; pure IPv6 CIDRs are silently skipped for now (the relay primarily
//! operates over IPv4).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Shared, hot-reloadable IP CIDR deny list.
/// Clone is O(1) — the inner `Arc<RwLock<…>>` is shared across all handlers.
#[derive(Clone)]
pub struct IpDenyList {
    entries: Arc<std::sync::RwLock<Vec<(u32, u32)>>>,
    path: Arc<Option<PathBuf>>,
}

impl IpDenyList {
    /// No deny list configured — all IPs are allowed.
    pub fn disabled() -> Self {
        Self {
            entries: Arc::new(std::sync::RwLock::new(Vec::new())),
            path: Arc::new(None),
        }
    }

    /// Load deny list from `path`. Logs a warning but does NOT fail startup if
    /// the file cannot be read — the relay operates with an empty deny list.
    pub fn from_file(path: &Path) -> Self {
        let entries = parse_denylist_file(path);
        tracing::info!(
            "ip-denylist: loaded {} CIDR(s) from {}",
            entries.len(),
            path.display()
        );
        Self {
            entries: Arc::new(std::sync::RwLock::new(entries)),
            path: Arc::new(Some(path.to_path_buf())),
        }
    }

    /// Atomically reload from the original file path.
    /// Errors are logged and the existing list is kept unchanged.
    pub fn reload(&self) {
        let Some(ref path) = *self.path else { return };
        let new_entries = parse_denylist_file(path);
        let count = new_entries.len();
        *self.entries.write().expect("IpDenyList RwLock poisoned") = new_entries;
        tracing::info!(
            "ip-denylist: reloaded {} CIDR(s) from {}",
            count,
            path.display()
        );
    }

    /// Returns `true` if `ip` is covered by any CIDR in the deny list.
    /// An empty list means no IPs are denied.
    pub fn is_denied(&self, ip: IpAddr) -> bool {
        let ip_u32 = match to_ipv4_u32(ip) {
            Some(v) => v,
            None => return false, // pure IPv6 — not matched
        };
        let entries = self.entries.read().expect("IpDenyList RwLock poisoned");
        entries.iter().any(|(net, mask)| ip_u32 & mask == *net)
    }

    /// `true` when a deny list file is configured (even if empty).
    pub fn is_enabled(&self) -> bool {
        self.path.is_some()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_denylist_file(path: &Path) -> Vec<(u32, u32)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                "ip-denylist: could not read {} — operating with empty deny list: {e}",
                path.display()
            );
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_cidr(line) {
            Some(entry) => entries.push(entry),
            None => tracing::warn!(
                "ip-denylist: {}:{} — invalid CIDR '{}', skipping",
                path.display(),
                lineno + 1,
                line
            ),
        }
    }
    entries
}

/// Parse a CIDR string like "192.168.0.0/16" into `(network_u32, mask_u32)`.
/// Returns `None` for malformed strings or pure IPv6.
fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = s.split_once('/')?;
    let prefix_len: u32 = prefix_str.parse().ok().filter(|&n| n <= 32)?;
    let ip: std::net::Ipv4Addr = ip_str.trim().parse().ok()?;
    let ip_u32 = u32::from(ip);
    let mask: u32 = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    Some((ip_u32 & mask, mask))
}

/// Convert an `IpAddr` to a u32 for CIDR matching.
/// Handles both plain IPv4 and IPv4-mapped IPv6 (`::ffff:x.x.x.x`).
fn to_ipv4_u32(ip: IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(v4) => Some(u32::from(v4)),
        IpAddr::V6(v6) => v6.to_ipv4().map(u32::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn disabled_denies_nothing() {
        let dl = IpDenyList::disabled();
        assert!(!dl.is_denied(v4(1, 2, 3, 4)));
        assert!(!dl.is_denied(v4(10, 0, 0, 1)));
    }

    #[test]
    fn single_cidr_match() {
        let entries = vec![parse_cidr("10.0.0.0/8").unwrap()];
        let dl = IpDenyList {
            entries: Arc::new(std::sync::RwLock::new(entries)),
            path: Arc::new(None),
        };
        assert!(dl.is_denied(v4(10, 0, 0, 1)));
        assert!(dl.is_denied(v4(10, 255, 255, 255)));
        assert!(!dl.is_denied(v4(11, 0, 0, 1)));
        assert!(!dl.is_denied(v4(192, 168, 1, 1)));
    }

    #[test]
    fn host_cidr_slash32() {
        let entries = vec![parse_cidr("1.2.3.4/32").unwrap()];
        let dl = IpDenyList {
            entries: Arc::new(std::sync::RwLock::new(entries)),
            path: Arc::new(None),
        };
        assert!(dl.is_denied(v4(1, 2, 3, 4)));
        assert!(!dl.is_denied(v4(1, 2, 3, 5)));
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_none());
        assert!(parse_cidr("256.0.0.0/8").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("10.0.0.0").is_none()); // no prefix
    }

    #[test]
    fn parse_cidr_slash0_matches_all() {
        let entry = parse_cidr("0.0.0.0/0").unwrap();
        // mask = 0, net = 0 → everything matches
        assert_eq!(entry, (0, 0));
    }
}
