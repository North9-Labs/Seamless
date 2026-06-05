// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! Lightweight in-process metrics — no external crates.
//!
//! All counters are `Arc<AtomicU64>` so they can be incremented from any task
//! and cheaply cloned into `AppState`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Prometheus-compatible histogram with fixed upper bounds.
///
/// Buckets are: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, +Inf
/// (seconds).  Each bucket counter is cumulative: `bucket[i]` counts
/// observations <= `BOUNDS[i]`.  `+Inf` == `count`.
#[derive(Clone)]
pub struct Histogram {
    /// Upper bounds in seconds (must be sorted ascending).
    bounds: &'static [f64],
    /// Cumulative bucket counters — `bucket[i]` = count of obs <= `bounds[i]`.
    buckets: Arc<Vec<AtomicU64>>,
    /// Total number of observations (== +Inf bucket).
    pub count: Arc<AtomicU64>,
    /// Sum of all observed values (in seconds).
    pub sum_us: Arc<AtomicU64>, // stored as microseconds to stay integer
}

/// Standard SLA buckets (seconds).
pub const LATENCY_BOUNDS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5];

impl Default for Histogram {
    fn default() -> Self {
        Self::new(LATENCY_BOUNDS)
    }
}

impl Histogram {
    pub fn new(bounds: &'static [f64]) -> Self {
        let buckets: Vec<AtomicU64> = (0..bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            bounds,
            buckets: Arc::new(buckets),
            count: Arc::new(AtomicU64::new(0)),
            sum_us: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record an observation of `secs` seconds.
    pub fn observe(&self, secs: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        // Store sum as integer microseconds to avoid floating-point atomics.
        let us = (secs * 1_000_000.0) as u64;
        self.sum_us.fetch_add(us, Ordering::Relaxed);
        for (i, &bound) in self.bounds.iter().enumerate() {
            if secs <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Render Prometheus exposition lines for this histogram.
    /// `name` must be the full metric name (e.g. `seamless_request_duration_seconds`).
    pub fn render_prometheus(&self, name: &str) -> String {
        let mut out = String::with_capacity(512);
        let count = self.count.load(Ordering::Relaxed);
        let sum_us = self.sum_us.load(Ordering::Relaxed);
        let sum_secs = sum_us as f64 / 1_000_000.0;
        for (i, &bound) in self.bounds.iter().enumerate() {
            let bucket_count = self.buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {bucket_count}\n"));
        }
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
        out.push_str(&format!("{name}_count {count}\n"));
        out.push_str(&format!("{name}_sum {sum_secs:.6}\n"));
        out
    }
}

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
    /// Total auth failures (missing or invalid token).
    pub auth_failures_total: Arc<AtomicU64>,
    /// Total connections rejected by the per-IP rate limiter.
    pub rate_limit_hits_total: Arc<AtomicU64>,
    /// Total connections rejected because the global tunnel cap was reached.
    pub tunnel_cap_rejections_total: Arc<AtomicU64>,
    /// Total subdomain validation failures.
    pub subdomain_invalid_total: Arc<AtomicU64>,
    /// Total connections rejected because the per-IP tunnel limit was reached.
    pub tunnel_per_ip_rejections_total: Arc<AtomicU64>,
    /// Histogram of proxied HTTP request durations (first byte to last byte sent).
    pub request_duration: Histogram,
    /// Currently active WebSocket connections being tunnelled.
    pub ws_connections_active: Arc<AtomicU64>,
    /// Total connections blocked by geo-IP country filter.
    pub geoip_blocked_total: Arc<AtomicU64>,
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

    pub fn inc_auth_failures(&self) {
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limit_hits(&self) {
        self.rate_limit_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tunnel_cap_rejections(&self) {
        self.tunnel_cap_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_subdomain_invalid(&self) {
        self.subdomain_invalid_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tunnel_per_ip_rejections(&self) {
        self.tunnel_per_ip_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ws_connections(&self) {
        self.ws_connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_ws_connections(&self) {
        self.ws_connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_geoip_blocked(&self) {
        self.geoip_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the duration of one proxied HTTP request (from first-byte-received to
    /// last-byte-sent).  `duration` is a `std::time::Duration`.
    pub fn record_request_duration(&self, duration: std::time::Duration) {
        self.request_duration.observe(duration.as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_counts_correctly() {
        let h = Histogram::new(LATENCY_BOUNDS);
        h.observe(0.003); // under 0.005
        h.observe(0.01); // exactly 0.01
        h.observe(0.5); // 0.5
        h.observe(5.0); // over all bounds

        assert_eq!(h.count.load(Ordering::Relaxed), 4);
        // bucket[0] = le 0.005: only 0.003
        assert_eq!(h.buckets[0].load(Ordering::Relaxed), 1);
        // bucket[1] = le 0.01: 0.003 + 0.01
        assert_eq!(h.buckets[1].load(Ordering::Relaxed), 2);
        // 0.5 falls in bucket index 6 (le 0.5)
        assert_eq!(h.buckets[6].load(Ordering::Relaxed), 3);
        // 5.0 falls in no regular bucket — only the +Inf (count)
        assert_eq!(h.buckets[8].load(Ordering::Relaxed), 3); // le 2.5: only 0.003, 0.01, 0.5
    }

    #[test]
    fn histogram_sum_accumulates() {
        let h = Histogram::new(LATENCY_BOUNDS);
        h.observe(0.1);
        h.observe(0.2);
        let sum_us = h.sum_us.load(Ordering::Relaxed);
        // 0.1 + 0.2 = 0.3 seconds = 300_000 us (allow small float rounding)
        assert!((290_000..310_000).contains(&sum_us), "sum_us was {sum_us}");
    }

    #[test]
    fn histogram_render_contains_buckets() {
        let h = Histogram::new(LATENCY_BOUNDS);
        h.observe(0.05);
        let rendered = h.render_prometheus("test_metric");
        assert!(rendered.contains("test_metric_bucket{le=\"0.005\"} 0"));
        assert!(rendered.contains("test_metric_bucket{le=\"0.05\"} 1"));
        assert!(rendered.contains("test_metric_bucket{le=\"+Inf\"} 1"));
        assert!(rendered.contains("test_metric_count 1"));
        assert!(rendered.contains("test_metric_sum "));
    }

    #[test]
    fn histogram_shared_across_clones() {
        let h1 = Histogram::new(LATENCY_BOUNDS);
        let h2 = h1.clone();
        h1.observe(0.1);
        h2.observe(0.2);
        assert_eq!(h1.count.load(Ordering::Relaxed), 2);
        assert_eq!(h2.count.load(Ordering::Relaxed), 2);
    }
}
