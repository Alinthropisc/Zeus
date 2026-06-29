//! BSD rlogin protocol authentication (RFC 1258), port 513.
//!
//! Wire flow:
//!   1. Bind a privileged source port (512–1022) — requires root.
//!   2. Connect to target port 513.
//!   3. Send: \x00 + client_username\x00 + server_username\x00 + terminal_type/speed\x00
//!   4. Read server null-byte ACK (\x00).
//!   5. If a password prompt appears, send `password\r\n` and inspect the response.

use async_trait::async_trait;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

use crate::resolve_addr;

pub struct RloginProtocol;

/// Read from `stream` until `\r\n` or `\n` is found, or EOF, with timeout.
async fn read_line_timeout(
    stream: &mut tokio::net::TcpStream,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, ZeusError> {
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 1];
    loop {
        match tokio::time::timeout(timeout, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(_)) => {
                buf.push(tmp[0]);
                if tmp[0] == b'\n' {
                    break;
                }
            }
            Ok(Err(e)) => return Err(ZeusError::Protocol(e.to_string())),
            Err(_) => break, // read timeout — treat as end of available data
        }
    }
    Ok(buf)
}

#[async_trait]
impl Protocol for RloginProtocol {
    fn name(&self) -> &'static str { "rlogin" }
    fn default_port(&self) -> u16 { 513 }
    fn description(&self) -> &'static str { "BSD rlogin password authentication (RFC 1258)" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr = resolve_addr(&target.host, target.port)?;
        let start = Instant::now();

        // rlogin requires a privileged source port (512–1023); try from 1022 down.
        let mut stream_opt: Option<tokio::net::TcpStream> = None;
        for src_port in (512u16..=1022).rev() {
            let socket = match TcpSocket::new_v4() {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = socket.set_reuseaddr(true);
            let local: std::net::SocketAddr =
                format!("0.0.0.0:{}", src_port).parse().unwrap();
            if socket.bind(local).is_err() {
                continue;
            }
            match tokio::time::timeout(config.timeout, socket.connect(addr)).await {
                Ok(Ok(s)) => {
                    stream_opt = Some(s);
                    break;
                }
                _ => continue,
            }
        }

        let mut stream = stream_opt.ok_or_else(|| {
            ZeusError::Protocol(
                "rlogin requires privileged source port (512-1023); run as root".into(),
            )
        })?;

        // Send rlogin handshake:
        //   \x00 + client_user\x00 + server_user\x00 + terminal/speed\x00
        let handshake = format!(
            "\x00{}\x00{}\x00vt100/9600\x00",
            cred.username, cred.username
        );
        tokio::time::timeout(config.timeout, stream.write_all(handshake.as_bytes()))
            .await
            .map_err(|_| ZeusError::Timeout(config.timeout))?
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read the server's null-byte ACK.
        let ack = read_line_timeout(&mut stream, config.timeout).await?;
        debug!("rlogin ACK: {:?}", ack);

        // Read the server's first output — may be a password prompt.
        let prompt_bytes = read_line_timeout(&mut stream, config.timeout).await?;
        let prompt_str = String::from_utf8_lossy(&prompt_bytes).to_lowercase();
        debug!("rlogin prompt: {:?}", prompt_str);

        if prompt_str.contains("ssword") || prompt_str.contains("assword") {
            // Send the password.
            let pass_line = format!("{}\r\n", cred.password);
            tokio::time::timeout(config.timeout, stream.write_all(pass_line.as_bytes()))
                .await
                .map_err(|_| ZeusError::Timeout(config.timeout))?
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;

            let resp_bytes = read_line_timeout(&mut stream, config.timeout).await?;
            let resp_str = String::from_utf8_lossy(&resp_bytes).to_lowercase();
            debug!("rlogin auth resp: {:?}", resp_str);

            let _ = stream.shutdown().await;

            if resp_str.contains("ssword")
                || resp_str.contains("ailure")
                || resp_str.contains("ncorrect")
                || resp_str.contains("denied")
            {
                Ok(AttackResult::Failure)
            } else {
                // Got a shell prompt or other non-error output — treat as success.
                Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                })
            }
        } else {
            // No password prompt — either trust-based login or an access denial.
            let _ = stream.shutdown().await;
            if prompt_str.contains("denied") || prompt_str.contains("refused") {
                Ok(AttackResult::Failure)
            } else {
                Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlogin_meta() {
        let p = RloginProtocol;
        assert_eq!(p.name(), "rlogin");
        assert_eq!(p.default_port(), 513);
    }

    #[test]
    fn rlogin_description_not_empty() {
        assert!(!RloginProtocol.description().is_empty());
    }
}
