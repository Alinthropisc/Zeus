use async_trait::async_trait;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct SnmpProtocol;

/// Build a minimal SNMPv1/v2c GET request BER-encoded.
/// Tests if the community string is valid by querying sysDescr (OID 1.3.6.1.2.1.1.1.0)
fn snmp_get_request(community: &str, version: u8) -> Vec<u8> {
    // OID 1.3.6.1.2.1.1.1.0 = sysDescr.0
    let oid: &[u8] = &[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let oid_encoded = [&[0x06u8, oid.len() as u8][..], oid].concat();

    // VarBind: SEQUENCE { OID, NULL }
    let null = [0x05u8, 0x00];
    let mut varbind = vec![0x30u8, (oid_encoded.len() + null.len()) as u8];
    varbind.extend_from_slice(&oid_encoded);
    varbind.extend_from_slice(&null);

    // VarBindList: SEQUENCE of VarBinds
    let mut varlist = vec![0x30u8, varbind.len() as u8];
    varlist.extend_from_slice(&varbind);

    // GetRequest-PDU [0]: request-id, error-status=0, error-index=0, varlist
    let req_id = [0x02u8, 0x01, 0x01]; // INTEGER 1
    let err_status = [0x02u8, 0x01, 0x00]; // INTEGER 0
    let err_index = [0x02u8, 0x01, 0x00]; // INTEGER 0

    let mut pdu_body = Vec::new();
    pdu_body.extend_from_slice(&req_id);
    pdu_body.extend_from_slice(&err_status);
    pdu_body.extend_from_slice(&err_index);
    pdu_body.extend_from_slice(&varlist);

    let mut pdu = vec![0xA0u8, pdu_body.len() as u8]; // GetRequest [0]
    pdu.extend_from_slice(&pdu_body);

    // Version: INTEGER (0=v1, 1=v2c)
    let ver = [0x02u8, 0x01, version];
    // Community: OCTET STRING
    let comm = community.as_bytes();
    let mut comm_enc = vec![0x04u8, comm.len() as u8];
    comm_enc.extend_from_slice(comm);

    let mut msg_body = Vec::new();
    msg_body.extend_from_slice(&ver);
    msg_body.extend_from_slice(&comm_enc);
    msg_body.extend_from_slice(&pdu);

    let mut msg = vec![0x30u8, msg_body.len() as u8]; // SEQUENCE
    msg.extend_from_slice(&msg_body);
    msg
}

#[async_trait]
impl Protocol for SnmpProtocol {
    fn name(&self) -> &'static str {
        "snmp"
    }
    fn default_port(&self) -> u16 {
        161
    }
    fn description(&self) -> &'static str {
        "SNMP community string brute-force (v1/v2c UDP). Password field = community string."
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr_str = format!("{}:{}", target.host, target.port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(ZeusError::Network)?
            .next()
            .ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let version_str = target
            .options
            .get("version")
            .map(String::as_str)
            .unwrap_or("1");
        let version: u8 = match version_str {
            "2c" | "2" => 1,
            _ => 0,
        };

        let community = &cred.password; // community string is the "password"
        let packet = snmp_get_request(community, version);

        let start = Instant::now();

        // SNMP runs over UDP — use blocking socket in spawn_blocking
        let addr_clone = addr;
        let packet_clone = packet.clone();
        let timeout_dur = config.timeout;

        let result = tokio::task::spawn_blocking(move || -> Result<bool, String> {
            let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(timeout_dur))
                .map_err(|e| e.to_string())?;
            socket
                .send_to(&packet_clone, addr_clone)
                .map_err(|e| e.to_string())?;
            let mut buf = [0u8; 1024];
            match socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    debug!("SNMP response bytes: {}", n);
                    // Any response = community string accepted
                    Ok(n > 0)
                }
                Err(_) => Ok(false), // timeout = wrong community
            }
        })
        .await
        .map_err(|e| ZeusError::Protocol(e.to_string()))?
        .map_err(ZeusError::Protocol)?;

        if result {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snmp_meta() {
        assert_eq!(SnmpProtocol.name(), "snmp");
        assert_eq!(SnmpProtocol.default_port(), 161);
    }

    #[test]
    fn snmp_packet_valid() {
        let pkt = snmp_get_request("public", 0);
        assert!(!pkt.is_empty());
        assert_eq!(pkt[0], 0x30); // SEQUENCE
    }
}
