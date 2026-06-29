//! WebSocket authentication-bypass research module.
//!
//! Adapter pattern — [`WebSocketAdapter`] wraps a plain TCP stream and
//! adds WebSocket framing on top, so the rest of the probe code deals only
//! with frames, not raw bytes.
//!
//! **Educational / defensive research use only.**

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::debug;
use crate::output::finding::Severity;

// WebSocket magic GUID defined in RFC 6455.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ─── upgraded connection state ────────────────────────────────────────────────

/// Represents a successfully upgraded WebSocket connection.
#[derive(Debug)]
pub struct WsConnection {
    /// Confirmed server `Sec-WebSocket-Accept` value.
    pub accept_key: String,
    /// Status code returned during the upgrade handshake.
    pub handshake_status: u16,
}

// ─── adapter ─────────────────────────────────────────────────────────────────

/// Adapter pattern: wraps a raw TCP stream and exposes a WebSocket framing API.
pub struct WebSocketAdapter {
    stream: TcpStream,
    handshake_headers: HashMap<String, String>,
}

impl WebSocketAdapter {
    /// Open a TCP connection to `host:port` and prepare for a WS upgrade to
    /// `path`.  The TCP connection is established here; the HTTP Upgrade
    /// request is sent later via [`upgrade_with_token`].
    pub async fn connect(host: &str, port: u16, path: &str) -> Result<Self> {
        let addr = format!("{host}:{port}");
        let stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;
        stream.set_nodelay(true)?;

        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), format!("{host}:{port}"));
        headers.insert("Path".to_string(), path.to_string());
        headers.insert("User-Agent".to_string(), "Zeus-WS-Probe/1.0".to_string());

        debug!("WebSocketAdapter connected to {addr}");
        Ok(Self { stream, handshake_headers: headers })
    }

    /// Send an HTTP/1.1 Upgrade request using `token` as the
    /// `Authorization: Bearer <token>` header and return a [`WsConnection`] if
    /// the server responds with `101 Switching Protocols`.
    ///
    /// This is the core of the token-replay bypass check: the caller can pass
    /// a token obtained during an earlier HTTP session; if the server accepts
    /// it during WS upgrade, per-request auth is being bypassed.
    pub async fn upgrade_with_token(&mut self, token: &str) -> Result<WsConnection> {
        let path = self.handshake_headers
            .get("Path")
            .map(String::as_str)
            .unwrap_or("/");
        let host = self.handshake_headers
            .get("Host")
            .map(String::as_str)
            .unwrap_or("");

        // Generate a random 16-byte nonce, base64-encoded per RFC 6455 §4.1.
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = B64.encode(nonce_bytes);

        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {nonce}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Authorization: Bearer {token}\r\n\
             \r\n"
        );

        timeout(
            Duration::from_secs(10),
            self.stream.write_all(request.as_bytes()),
        )
        .await??;

        // Read the server's handshake response.
        let raw = timeout(Duration::from_secs(10), read_until_blank_line(&mut self.stream))
            .await??;
        let text = String::from_utf8_lossy(&raw);

        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        if status != 101 {
            return Err(anyhow!("WS upgrade rejected: HTTP {status}"));
        }

        // Verify the accept key matches RFC 6455 §4.1.
        let expected = ws_accept_key(&nonce);
        let accept_key = text
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-accept:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|v| v.trim().to_string())
            .unwrap_or_default();

        if accept_key != expected {
            return Err(anyhow!(
                "WS accept key mismatch: expected={expected} got={accept_key}"
            ));
        }

        debug!("WS upgrade OK: status=101");
        Ok(WsConnection { accept_key, handshake_status: status })
    }

    /// Send a WebSocket text frame containing `payload`.
    ///
    /// Frames are masked with a random 4-byte masking key as required by
    /// RFC 6455 §5.3 for client-to-server frames.
    pub async fn send_frame(
        &mut self,
        _conn: &mut WsConnection,
        payload: &[u8],
    ) -> Result<()> {
        let frame = build_ws_frame(0x01 /* text */, payload);
        timeout(Duration::from_secs(10), self.stream.write_all(&frame)).await??;
        Ok(())
    }

    /// Receive a single WebSocket frame and return its payload.
    ///
    /// Handles both small (≤125 byte) and extended (16-bit length) payloads.
    /// Unmasked server frames are accepted per RFC 6455 §5.1.
    pub async fn recv_frame(&mut self, _conn: &mut WsConnection) -> Result<Vec<u8>> {
        let mut header = [0u8; 2];
        timeout(Duration::from_secs(10), self.stream.read_exact(&mut header)).await??;

        let _fin  = (header[0] & 0x80) != 0;
        let _opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let len_byte = (header[1] & 0x7F) as usize;

        let payload_len = if len_byte == 126 {
            let mut ext = [0u8; 2];
            timeout(Duration::from_secs(10), self.stream.read_exact(&mut ext)).await??;
            u16::from_be_bytes(ext) as usize
        } else if len_byte == 127 {
            let mut ext = [0u8; 8];
            timeout(Duration::from_secs(10), self.stream.read_exact(&mut ext)).await??;
            u64::from_be_bytes(ext) as usize
        } else {
            len_byte
        };

        let mask = if masked {
            let mut m = [0u8; 4];
            timeout(Duration::from_secs(10), self.stream.read_exact(&mut m)).await??;
            Some(m)
        } else {
            None
        };

        let mut payload = vec![0u8; payload_len];
        timeout(Duration::from_secs(10), self.stream.read_exact(&mut payload)).await??;

        if let Some(m) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= m[i % 4];
            }
        }

        Ok(payload)
    }
}

// ─── probes ──────────────────────────────────────────────────────────────────

/// Result of a WebSocket authentication probe.
#[derive(Debug, Clone)]
pub struct WsProbeResult {
    pub bypass_detected: bool,
    pub finding: String,
    pub severity: Severity,
}

/// Probes that test whether the WebSocket upgrade path bypasses auth checks.
pub struct WebSocketAuthProbe {
    /// How long to keep attempting token replay before giving up.
    pub replay_window_ms: u64,
}

impl WebSocketAuthProbe {
    /// **Token replay probe**: does replaying an HTTP-session token during the
    /// WS upgrade succeed even after the HTTP session has expired?
    ///
    /// The probe attempts the upgrade repeatedly within `replay_window_ms`,
    /// sleeping 100 ms between attempts, to account for small clock skew.
    pub async fn probe_token_replay(
        &self,
        adapter: &mut WebSocketAdapter,
        token: &str,
    ) -> Result<WsProbeResult> {
        let deadline = Duration::from_millis(self.replay_window_ms);
        let start = tokio::time::Instant::now();

        let mut last_err = String::new();

        while start.elapsed() < deadline {
            match adapter.upgrade_with_token(token).await {
                Ok(_conn) => {
                    return Ok(WsProbeResult {
                        bypass_detected: true,
                        finding: format!(
                            "Token replay accepted during WS upgrade after {}ms — \
                             per-request auth is not enforced at the WebSocket layer",
                            start.elapsed().as_millis()
                        ),
                        severity: Severity::High,
                    });
                }
                Err(e) => {
                    last_err = e.to_string();
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }

        Ok(WsProbeResult {
            bypass_detected: false,
            finding: format!("Token replay rejected throughout window: {last_err}"),
            severity: Severity::Info,
        })
    }

    /// **Origin bypass probe**: does the server accept a WS upgrade with a
    /// cross-origin `Origin` header?  A missing or permissive `Origin` check
    /// allows DNS-rebinding and CSRF-via-WebSocket attacks.
    pub async fn probe_origin_bypass(
        &self,
        adapter: &mut WebSocketAdapter,
    ) -> Result<WsProbeResult> {
        let path = adapter
            .handshake_headers
            .get("Path")
            .map(String::as_str)
            .unwrap_or("/");
        let host = adapter
            .handshake_headers
            .get("Host")
            .map(String::as_str)
            .unwrap_or("");

        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = B64.encode(nonce_bytes);

        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {nonce}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Origin: https://evil.attacker.com\r\n\
             \r\n"
        );

        timeout(
            Duration::from_secs(10),
            adapter.stream.write_all(request.as_bytes()),
        )
        .await??;

        let raw = timeout(
            Duration::from_secs(10),
            read_until_blank_line(&mut adapter.stream),
        )
        .await??;
        let text = String::from_utf8_lossy(&raw);

        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        let bypass_detected = status == 101;
        Ok(WsProbeResult {
            bypass_detected,
            finding: if bypass_detected {
                "Server accepted WS upgrade from cross-origin 'https://evil.attacker.com' \
                 — Origin header not validated"
                    .to_string()
            } else {
                format!("Cross-origin WS upgrade rejected: HTTP {status}")
            },
            severity: if bypass_detected { Severity::High } else { Severity::Info },
        })
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Compute the `Sec-WebSocket-Accept` value for a given nonce (RFC 6455 §4.1).
fn ws_accept_key(nonce: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(nonce.as_bytes());
    sha.update(WS_GUID.as_bytes());
    B64.encode(sha.finalize())
}

/// Build a masked WebSocket frame (RFC 6455 §5.2).
fn build_ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);

    // FIN bit set, RSV clear, opcode in lower nibble.
    frame.push(0x80 | (opcode & 0x0F));

    // Mask bit set; extended length if needed.
    let len = payload.len();
    if len <= 125 {
        frame.push(0x80 | len as u8);
    } else if len <= 65535 {
        frame.push(0x80 | 126u8);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127u8);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }

    // 4-byte masking key.
    let mask: [u8; 4] = rand::random();
    frame.extend_from_slice(&mask);

    // Masked payload.
    for (i, &byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i % 4]);
    }

    frame
}

/// Read bytes from `stream` until a blank line (`\r\n\r\n`) is found.
async fn read_until_blank_line(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 256];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("connection closed before end of HTTP headers"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(buf)
}
