// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! Geo-IP country blocking using a local MaxMind GeoLite2-Country database.
//!
//! When `--geoip-db` is not supplied or the file cannot be opened, geo-blocking
//! is disabled and a startup warning is emitted.  This is intentional: the relay
//! operates correctly without a DB — operators opt into geo-blocking explicitly.
//!
//! Database format: MaxMind DB binary (`.mmdb`).  The `maxminddb` crate reads
//! it directly from disk into a `Vec<u8>` at startup — no runtime DB queries.
//!
//! Usage:
//! ```text
//! seamless-relay --geoip-db /var/lib/seamless/GeoLite2-Country.mmdb \
//!                --block-countries CN,RU,KP,IR
//! ```

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;

/// Running total of connections blocked by geo-IP filtering.
pub static GEOIP_BLOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Geo-IP filter backed by a local MaxMind GeoLite2-Country `.mmdb` file.
///
/// Clone is O(1) via the inner `Arc` on the `maxminddb::Reader`.
pub struct GeoipFilter {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    blocked_countries: HashSet<String>,
}

impl GeoipFilter {
    /// Create a new filter.
    ///
    /// `db_path` — path to `GeoLite2-Country.mmdb`.  Pass `None` to disable
    /// geo-blocking entirely (all IPs are allowed).
    ///
    /// `countries` — ISO 3166-1 alpha-2 codes to block, e.g. `["CN", "RU"]`.
    /// Case-insensitive; stored as uppercase.
    pub fn new(db_path: Option<&str>, countries: Vec<String>) -> Result<Self> {
        let blocked_countries: HashSet<String> = countries
            .into_iter()
            .map(|c| c.trim().to_uppercase())
            .filter(|c| !c.is_empty())
            .collect();

        let reader = match db_path {
            None => {
                if !blocked_countries.is_empty() {
                    tracing::warn!(
                        "geoip: --block-countries is set but --geoip-db is not — \
                         geo-blocking is DISABLED (provide a GeoLite2-Country.mmdb path)"
                    );
                }
                None
            }
            Some(path) => match maxminddb::Reader::open_readfile(path) {
                Ok(r) => {
                    tracing::info!(
                        "geoip: loaded database from {path} ({} blocked country/ies: {})",
                        blocked_countries.len(),
                        blocked_countries
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    Some(r)
                }
                Err(e) => {
                    tracing::warn!(
                        "geoip: could not open database at {path}: {e} — \
                             geo-blocking is DISABLED"
                    );
                    None
                }
            },
        };

        Ok(Self {
            reader,
            blocked_countries,
        })
    }

    /// Disabled filter — no DB, no blocked countries.  All IPs pass.
    pub fn disabled() -> Self {
        Self {
            reader: None,
            blocked_countries: HashSet::new(),
        }
    }

    /// Returns `true` if `ip` belongs to a blocked country.
    ///
    /// Returns `false` when:
    /// - No DB is loaded.
    /// - No countries are configured.
    /// - The IP cannot be looked up (private ranges, etc.).
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let reader = match &self.reader {
            Some(r) => r,
            None => return false,
        };
        if self.blocked_countries.is_empty() {
            return false;
        }
        match self.lookup_country(reader, ip) {
            Some(cc) if self.blocked_countries.contains(&cc) => {
                GEOIP_BLOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }

    /// Return the ISO 3166-1 alpha-2 country code for `ip`, or `None` if
    /// the DB is not loaded or the IP is not in the database.
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        self.lookup_country(reader, ip)
    }

    /// Returns `true` if a database is loaded (geo-blocking may be active).
    pub fn is_enabled(&self) -> bool {
        self.reader.is_some() && !self.blocked_countries.is_empty()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn lookup_country(&self, reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> Option<String> {
        let record: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;
        let cc = record.country?.iso_code?;
        Some(cc.to_uppercase())
    }
}
