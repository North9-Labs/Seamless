// Copyright (c) 2025 North9 LLC
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared types for the Seamless reverse-tunnel wire protocol.
//!
//! Every Seam connection between client and relay begins with the client
//! opening the first stream as the **control stream**. All frames on it are
//! `ControlFrame` values, length-prefixed with a 4-byte big-endian u32.
//!
//! Data streams (every stream opened by the relay after registration) begin
//! with a single `NewConnPreamble` frame, then carry raw TCP bytes.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelKind {
    /// HTTP(S) routed on the relay by Host header matching `subdomain`.
    Http { subdomain: Option<String> },
    /// Raw TCP on a dedicated relay port (0 = relay picks one).
    Tcp { port: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlFrame {
    /// Client → Relay. Must be the first frame on the control stream.
    Register {
        version: u8,
        token: Option<String>,
        kind: TunnelKind,
    },
    /// Relay → Client. Sent once after a successful Register.
    Registered {
        public_url: String,
    },
    /// Relay → Client. Sent on the *data stream* as its preamble (not control).
    /// Carried here so there is a single `ControlFrame` enum to decode.
    NewConn {
        peer_addr: String,
    },
    /// Either side. Non-fatal keepalive.
    Ping,
    /// Either side. Fatal — close the connection after sending.
    Error {
        code: u16,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes (limit {MAX_FRAME_BYTES})")]
    TooLarge(u32),
    #[error("decode: {0}")]
    Decode(#[from] bincode::Error),
    #[error("unexpected eof")]
    Eof,
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &ControlFrame,
) -> Result<(), CodecError> {
    let body = bincode::serialize(frame)?;
    let len = u32::try_from(body.len()).map_err(|_| CodecError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_BYTES {
        return Err(CodecError::TooLarge(len));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<ControlFrame, CodecError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CodecError::Eof
        } else {
            CodecError::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(CodecError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(bincode::deserialize(&body)?)
}
