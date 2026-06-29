//! Protocol implementations — Strategy pattern.
//! Each module implements `zeus_core::Protocol`.

use std::net::{SocketAddr, ToSocketAddrs};
use zeus_core::ZeusError;

/// Resolve `host:port` to a `SocketAddr`, returning `ZeusError` on failure.
/// Used by every protocol to avoid duplicating DNS resolution code.
#[allow(dead_code)]
pub(crate) fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr, ZeusError> {
    format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(ZeusError::Network)?
        .next()
        .ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))
}

pub mod adam6500;
pub mod afp;
pub mod cisco_enable;
pub mod cobaltstrike;
pub mod cvs;
pub mod ftp;
pub mod http;
pub mod http_form;
pub mod http_proxy;
pub mod http_proxy_urlenum;
pub mod icq;
pub mod imap;
pub mod irc;
pub mod ldap;
pub mod ncp;
pub mod nntp;
pub mod pcanywhere;
pub mod pcnfs;
pub mod pop3;
pub mod radmin2;
pub mod rdp;
pub mod rexec;
pub mod rlogin;
pub mod rpcap;
pub mod rsh;
pub mod rtsp;
pub mod s7_300;
pub mod sapr3;
pub mod sip;
pub mod smb;
pub mod smtp;
pub mod smtp_enum;
pub mod snmp;
pub mod socks5;
pub mod ssh_stub;
pub mod sshkey;
pub mod svn;
pub mod teamspeak;
pub mod telnet;
pub mod vmauthd;
pub mod vnc;
pub mod xmpp;

pub use adam6500::Adam6500Protocol;
pub use afp::AfpProtocol;
pub use cisco_enable::CiscoEnableProtocol;
pub use cobaltstrike::CobaltStrikeProtocol;
pub use cvs::CvsProtocol;
pub use ftp::FtpProtocol;
pub use http::HttpProtocol;
pub use http_form::HttpFormProtocol;
pub use http_proxy::HttpProxyProtocol;
pub use http_proxy_urlenum::HttpProxyUrlEnumProtocol;
pub use icq::IcqProtocol;
pub use imap::ImapProtocol;
pub use irc::IrcProtocol;
pub use ldap::LdapProtocol;
pub use ncp::NcpProtocol;
pub use nntp::NntpProtocol;
pub use pcanywhere::PcAnywhereProtocol;
pub use pcnfs::PcNfsProtocol;
pub use pop3::Pop3Protocol;
pub use radmin2::Radmin2Protocol;
pub use rdp::RdpProtocol;
pub use rexec::RexecProtocol;
pub use rlogin::RloginProtocol;
pub use rpcap::RpcapProtocol;
pub use rsh::RshProtocol;
pub use rtsp::RtspProtocol;
pub use s7_300::S7300Protocol;
pub use sapr3::SapR3Protocol;
pub use sip::SipProtocol;
pub use smb::SmbProtocol;
pub use smtp::SmtpProtocol;
pub use smtp_enum::SmtpEnumProtocol;
pub use snmp::SnmpProtocol;
pub use socks5::Socks5Protocol;
pub use ssh_stub::SshProtocol;
pub use sshkey::SshKeyProtocol;
pub use svn::SvnProtocol;
pub use teamspeak::TeamSpeakProtocol;
pub use telnet::TelnetProtocol;
pub use vmauthd::VmauthdProtocol;
pub use vnc::VncProtocol;
pub use xmpp::XmppProtocol;
