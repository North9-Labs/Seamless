// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! Lightweight in-process metrics — no external crates.
//!
//! All counters are `Arc<AtomicU64>` so they can be incremented from any task
//! and cheaply cloned into `AppState`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A set of shared atomic counters updated by ingress and tunnel code.
#[derive(Clone, Default)]
pub struct Metrics {
    /// Bytes received from public clients and forwarded into tunnels.
    pub bytes_in: Arc<AtomicU64>,
    /// Bytes received from tunnels and sent to public clients.
    pub bytes_out: Arc<AtomicU64>,
    /// Total number of connections accepted on the ingress (ever, since boot).
    pub connections_total: Arc<AtomicU64>,
    /// Sum of all handshake durations in milliseconds (divide by `connections_total` for avg).
    pub handshake_ms_total: Arc<AtomicU64>,
    /// Number of completed handshakes (used as denominator for the avg).
    pub handshake_count: Arc<AtomicU64>,
}

pub fn new_metrics() -> Metrics {
    Metrics::default()
}

impl Metrics {
    pub fn inc_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_connections(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_handshake_ms(&self, ms: u64) {
        self.handshake_ms_total.fetch_add(ms, Ordering::Relaxed);
        self.handshake_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn handshake_avg_ms(&self) -> f64 {
        let count = self.handshake_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.handshake_ms_total.load(Ordering::Relaxed) as f64 / count as f64
    }
}
