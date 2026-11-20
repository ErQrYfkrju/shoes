//! Transport-related configuration types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationPortRange};
use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};

use super::common::default_true;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BindLocation {
    #[serde(alias = "addresses")]
    Address(OneOrSome<NetLocationPortRange>),
    Path(PathBuf),
    #[serde(untagged)]
    Unspecified {},
}

impl std::fmt::Display for BindLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindLocation::Address(addresses) => {
                for (index, address) in addresses.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{address}")?;
                }
                Ok(())
            }
            BindLocation::Path(p) => write!(f, "{}", p.display()),
            BindLocation::Unspecified {} => f.write_str("no listener"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Tcp,
    Quic,
    Udp,
    Kcp,
}

impl Transport {
    /// Returns true if this is the default transport (TCP)
    pub fn is_default(&self) -> bool {
        matches!(self, Transport::Tcp)
    }
}

pub const DEFAULT_KCP_MAX_SESSIONS: u32 = 1024;
const KCP_WIRE_OVERHEAD: u32 = 24;
const KCP_MAX_MTU: u32 = 65_535;
const KCP_MAX_WINDOW: u32 = u16::MAX as u32;

/// KCP performance mode presets.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum KcpMode {
    #[default]
    Normal,
    Fast,
    Turbo,
    Gaming,
    #[serde(alias = "filetransfer")]
    FileTransfer,
}

/// Validated KCP settings shared by client and server configurations.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KcpSettings {
    #[serde(default)]
    pub mode: KcpMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_window: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_window: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default = "default_kcp_max_sessions")]
    pub max_sessions: u32,
}

const fn default_kcp_max_sessions() -> u32 {
    DEFAULT_KCP_MAX_SESSIONS
}

impl Default for KcpSettings {
    fn default() -> Self {
        Self {
            mode: KcpMode::Normal,
            send_window: None,
            recv_window: None,
            mtu: None,
            max_sessions: DEFAULT_KCP_MAX_SESSIONS,
        }
    }
}

impl KcpSettings {
    pub(crate) fn validate(&self) -> std::io::Result<()> {
        if self.max_sessions == 0 {
            return Err(invalid_kcp_field(
                "max_sessions",
                "must be greater than zero",
            ));
        }

        match (self.send_window, self.recv_window) {
            (None, None) => {}
            (Some(send), Some(recv)) => {
                for (field, value) in [("send_window", send), ("recv_window", recv)] {
                    if value == 0 || value > KCP_MAX_WINDOW {
                        return Err(invalid_kcp_field(
                            field,
                            format!("must be in 1..={KCP_MAX_WINDOW}, got {value}"),
                        ));
                    }
                }
            }
            _ => {
                return Err(invalid_kcp_field(
                    "send_window/recv_window",
                    "send_window and recv_window must be specified together",
                ));
            }
        }

        if let Some(mtu) = self.mtu
            && (mtu <= KCP_WIRE_OVERHEAD || mtu > KCP_MAX_MTU)
        {
            return Err(invalid_kcp_field(
                "mtu",
                format!(
                    "must be in {}..={KCP_MAX_MTU}, got {mtu}",
                    KCP_WIRE_OVERHEAD + 1
                ),
            ));
        }
        Ok(())
    }
}

fn invalid_kcp_field(field: &str, message: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("kcp_settings.{field}: {message}"),
    )
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub no_delay: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig { no_delay: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerQuicConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_source: Option<String>,
    #[serde(skip)]
    pub certificate_binding: Option<std::sync::Arc<crate::certificates::Source>>,
    #[serde(
        default,
        skip_serializing_if = "super::tls::TlsKeyExchangeGroups::is_default"
    )]
    pub key_exchange_groups: super::tls::TlsKeyExchangeGroups,
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(alias = "client_ca_cert", default)]
    pub client_ca_certs: NoneOrSome<String>,
    #[serde(alias = "client_fingerprint", default)]
    pub client_fingerprints: NoneOrSome<String>,
    // num_endpoints of 0 will use the number of threads as the default value.
    #[serde(default)]
    pub num_endpoints: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientQuicConfig {
    #[serde(
        default,
        skip_serializing_if = "super::tls::TlsKeyExchangeGroups::is_default"
    )]
    pub key_exchange_groups: super::tls::TlsKeyExchangeGroups,
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(alias = "server_fingerprint", default)]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default)]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
}

impl Default for ClientQuicConfig {
    fn default() -> Self {
        Self {
            key_exchange_groups: Default::default(),
            verify: true,
            server_fingerprints: NoneOrSome::Unspecified,
            sni_hostname: NoneOrOne::Unspecified,
            alpn_protocols: NoneOrSome::Unspecified,
            key: None,
            cert: None,
        }
    }
}

impl From<NetLocation> for BindLocation {
    fn from(loc: NetLocation) -> Self {
        BindLocation::Address(OneOrSome::One(loc.into()))
    }
}
