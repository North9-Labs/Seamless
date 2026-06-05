// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! Append-only JSONL audit log with midnight rotation.
//!
//! Government compliance requires a persistent, immutable audit trail separate
//! from the main operational log.  This module writes every structured audit
//! event (`tunnel.open`, `tunnel.close`, `auth.failure`, `ip.denylisted`, etc.)
//! to a JSONL file (`--audit-log <path>`).
//!
//! # Rotation
//! At midnight UTC the current file is renamed to `<path>.YYYY-MM-DD` and a
//! fresh file is opened.  The rotation is performed lazily on the next write
//! that crosses a day boundary — no extra background task is needed.
//!
//! # Performance
//! All writes are dispatched via a `tokio::sync::mpsc` channel so the caller
//! never blocks waiting for disk I/O.  The channel buffer is 8 192 events;
//! when full, excess events are dropped and a warning is emitted (this should
//! never happen in normal operation).
//!
//! # Integrity
//! Each line is terminated with `\n`.  The file is opened in append mode so
//! multiple relay instances can safely write to separate files.  No locking
//! or checksumming is performed at this layer — use filesystem-level integrity
//! tools (e.g. auditd, dm-integrity) for tamper-evidence requirements.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

/// In-memory ring buffer of the most recent audit events.
/// Capacity is 1 024 entries — enough for a monitoring poll interval of minutes
/// at even high event rates without significant memory cost.
const RING_CAPACITY: usize = 1_024;

/// Shared, append-only in-memory ring of recent audit events.
/// Cloning is O(1) (Arc clone).
#[derive(Clone, Default)]
pub struct AuditRing {
    inner: Arc<Mutex<VecDeque<Value>>>,
}

impl AuditRing {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(RING_CAPACITY))),
        }
    }

    pub async fn push(&self, event: Value) {
        let mut buf = self.inner.lock().await;
        if buf.len() >= RING_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(event);
    }

    /// Return up to `limit` events whose `ts` field is >= `since_ts`.
    /// Events are returned in chronological order (oldest first).
    pub async fn query(&self, since_ts: Option<i64>, limit: usize) -> Vec<Value> {
        let buf = self.inner.lock().await;
        buf.iter()
            .filter(|ev| {
                if let Some(since) = since_ts {
                    ev.get("ts").and_then(Value::as_i64).unwrap_or(0) >= since
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect()
    }
}

/// A cheap clone handle to the audit log writer background task.
/// Sending is fire-and-forget; the background task handles all I/O.
#[derive(Clone)]
pub struct AuditLog {
    tx: Option<mpsc::Sender<Value>>,
    /// In-memory ring buffer of recent events — queryable via `GET /admin/audit`.
    pub ring: AuditRing,
}

impl AuditLog {
    /// Returns a no-op handle when `--audit-log` is not configured.
    /// The in-memory ring is still active (events are always kept in memory).
    pub fn disabled() -> Self {
        Self { tx: None, ring: AuditRing::new() }
    }

    /// Spawn the background writer task and return a handle.
    /// `path` is the base path (e.g. `/var/log/seamless/audit.jsonl`).
    pub fn start(path: PathBuf) -> Self {
        let (tx, rx) = mpsc::channel::<Value>(8_192);
        let ring = AuditRing::new();
        tokio::spawn(writer_task(path, rx));
        Self { tx: Some(tx), ring }
    }

    /// Emit an audit event.  Non-blocking — drops the event if the channel is full
    /// (logged as a warning in the writer task).
    /// Always writes to the in-memory ring regardless of whether file logging is enabled.
    /// Must be called from within a Tokio runtime context.
    pub fn emit(&self, event: Value) {
        // Push to the in-memory ring.
        // Use try_lock for the fast path (lock usually uncontended); if the lock is
        // held, spawn a task so the caller is never blocked.  In both cases the ring
        // is updated without a blocking `await` on the hot path.
        let ev_clone = event.clone();
        let pushed_inline = {
            let ring = &self.ring;
            match ring.inner.try_lock() {
                Ok(mut buf) => {
                    if buf.len() >= RING_CAPACITY {
                        buf.pop_front();
                    }
                    buf.push_back(ev_clone);
                    true
                }
                Err(_) => false,
            }
        };
        if !pushed_inline {
            let ring = self.ring.clone();
            let ev2 = event.clone();
            tokio::spawn(async move { ring.push(ev2).await });
        }

        if let Some(ref tx) = self.tx {
            if tx.try_send(event).is_err() {
                tracing::warn!("audit-log: channel full — event dropped (disk I/O too slow?)");
            }
        }
    }

    /// Returns `true` when a log file path is configured.
    pub fn is_enabled(&self) -> bool {
        self.tx.is_some()
    }
}

// ── Background writer ─────────────────────────────────────────────────────────

async fn writer_task(base_path: PathBuf, mut rx: mpsc::Receiver<Value>) {
    let mut state = WriterState::new(base_path);

    while let Some(event) = rx.recv().await {
        if let Err(e) = state.write_event(&event).await {
            tracing::error!("audit-log: write failed: {e:#}");
        }
    }
}

struct WriterState {
    base_path: PathBuf,
    /// The file handle currently being written to.
    file: Option<tokio::fs::File>,
    /// The calendar date (UTC) when `file` was opened — used to detect midnight crossover.
    open_date: Option<(i32, u32, u32)>, // (year, month, day)
}

impl WriterState {
    fn new(base_path: PathBuf) -> Self {
        Self {
            base_path,
            file: None,
            open_date: None,
        }
    }

    async fn write_event(&mut self, event: &Value) -> anyhow::Result<()> {
        let today = utc_date_today();

        // Rotate at midnight: rename the old file and open a fresh one.
        if self.open_date.is_some() && self.open_date != Some(today) {
            self.rotate(self.open_date.unwrap()).await;
        }

        // Open the file if not already open.
        if self.file.is_none() {
            self.file = Some(open_log_file(&self.base_path).await?);
            self.open_date = Some(today);
            tracing::info!(
                "audit-log: opened {}",
                self.base_path.display()
            );
        }

        // Serialize and write.
        let line = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string());
        let file = self.file.as_mut().expect("file must be Some after open");
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        // We do NOT fsync after every write — that would be prohibitively slow.
        // Operators requiring synchronous durability should mount the filesystem
        // with `sync` or use `O_SYNC` at the OS level.
        Ok(())
    }

    /// Rename the current log file to `<base>.YYYY-MM-DD` and close the handle.
    async fn rotate(&mut self, old_date: (i32, u32, u32)) {
        // Flush and close the existing handle before renaming.
        if let Some(mut f) = self.file.take() {
            let _ = f.flush().await;
            drop(f);
        }
        self.open_date = None;

        let (y, m, d) = old_date;
        let rotated = PathBuf::from(format!(
            "{}.{:04}-{:02}-{:02}",
            self.base_path.display(),
            y, m, d
        ));
        match tokio::fs::rename(&self.base_path, &rotated).await {
            Ok(()) => tracing::info!(
                "audit-log: rotated to {}",
                rotated.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Nothing to rotate — the file was never written (e.g. day with no events).
            }
            Err(e) => tracing::warn!(
                "audit-log: rotation rename failed ({} → {}): {e}",
                self.base_path.display(),
                rotated.display()
            ),
        }
    }
}

/// Open (or create) the audit log file in append mode.
/// Creates parent directories if they do not exist.
async fn open_log_file(path: &Path) -> anyhow::Result<tokio::fs::File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    Ok(file)
}

/// Return the current UTC date as `(year, month, day)`.
fn utc_date_today() -> (i32, u32, u32) {
    // We use std::time to avoid pulling in a date/time crate.
    // Compute from epoch seconds: good enough for midnight rotation.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_to_ymd(secs)
}

/// Rudimentary epoch-seconds → (year, month, day) in UTC.
/// Accurate for the Gregorian calendar from 1970 onward.
fn epoch_to_ymd(secs: u64) -> (i32, u32, u32) {
    // Algorithm: https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

// ── Convenience macro for emitting typed events ───────────────────────────────

/// Emit a structured audit event with a guaranteed `ts` (Unix seconds) field.
/// Usage:
/// ```ignore
/// audit_event!(audit_log, "tunnel.open", "subdomain" => sub, "client_ip" => ip);
/// ```
#[macro_export]
macro_rules! audit_event {
    ($log:expr, $event:expr, $($key:expr => $val:expr),* $(,)?) => {{
        let mut map = serde_json::Map::new();
        map.insert("ts".to_string(), serde_json::json!(crate::store::unix_now()));
        map.insert("event".to_string(), serde_json::json!($event));
        $(
            map.insert($key.to_string(), serde_json::json!($val));
        )*
        $log.emit(serde_json::Value::Object(map));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_to_ymd_known_dates() {
        // 2025-01-01 00:00:00 UTC = 1735689600
        assert_eq!(epoch_to_ymd(1_735_689_600), (2025, 1, 1));
        // 2000-03-01 00:00:00 UTC = 951868800
        assert_eq!(epoch_to_ymd(951_868_800), (2000, 3, 1));
        // 1970-01-01
        assert_eq!(epoch_to_ymd(0), (1970, 1, 1));
        // 2024-02-29 (leap day) = 1709164800
        assert_eq!(epoch_to_ymd(1_709_164_800), (2024, 2, 29));
    }

    #[test]
    fn disabled_emit_noop() {
        let log = AuditLog::disabled();
        // Should not panic
        log.emit(serde_json::json!({"event": "test"}));
        assert!(!log.is_enabled());
    }

    #[tokio::test]
    async fn audit_ring_query_all() {
        let ring = AuditRing::new();
        ring.push(serde_json::json!({"event": "a", "ts": 100})).await;
        ring.push(serde_json::json!({"event": "b", "ts": 200})).await;
        ring.push(serde_json::json!({"event": "c", "ts": 300})).await;

        let all = ring.query(None, 100).await;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0]["event"], "a");
        assert_eq!(all[2]["event"], "c");
    }

    #[tokio::test]
    async fn audit_ring_query_since() {
        let ring = AuditRing::new();
        ring.push(serde_json::json!({"event": "old", "ts": 50})).await;
        ring.push(serde_json::json!({"event": "new", "ts": 200})).await;

        let recent = ring.query(Some(100), 100).await;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0]["event"], "new");
    }

    #[tokio::test]
    async fn audit_ring_respects_limit() {
        let ring = AuditRing::new();
        for i in 0..10 {
            ring.push(serde_json::json!({"event": "x", "ts": i})).await;
        }
        let capped = ring.query(None, 3).await;
        assert_eq!(capped.len(), 3);
    }

    #[tokio::test]
    async fn write_events_to_file() {
        let dir = std::env::temp_dir().join(format!("seamless-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");

        let log = AuditLog::start(path.clone());
        log.emit(serde_json::json!({"event": "test.event", "ts": 1}));
        log.emit(serde_json::json!({"event": "test.event2", "ts": 2}));

        // Give the background task time to flush.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(content.contains("test.event"), "expected test.event in {content}");
        assert!(content.contains("test.event2"), "expected test.event2 in {content}");
        // Each event on its own line
        assert_eq!(content.lines().count(), 2);

        // Clean up
        let _ = std::fs::remove_dir_all(&dir);
    }
}
