use std::collections::VecDeque;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub ts: i64,
    pub method: String,
    pub path: String,
    pub host: String,
    pub routed_to: String,
    pub status: u16,
}

pub const MAX_LOGS: usize = 500;
pub type LogBuffer = Arc<Mutex<VecDeque<LogEntry>>>;

pub fn new_buffer() -> LogBuffer {
    Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOGS)))
}

pub async fn push(buf: &LogBuffer, entry: LogEntry) {
    let mut q = buf.lock().await;
    if q.len() >= MAX_LOGS {
        q.pop_front();
    }
    q.push_back(entry);
}
