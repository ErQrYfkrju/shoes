//! KCP configuration conversion and listener support.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error};
use tokio::task::JoinHandle;
use tokio_kcp::{KcpConfig, KcpListener, KcpNoDelayConfig};

use crate::config::{BindLocation, KcpMode, KcpSettings, ResolvedServerConfig};
use crate::kcp_stream::KcpStreamWrapper;
use crate::resolver::Resolver;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tcp::tcp_server::process_stream;
use crate::tcp::tcp_server_handler_factory::{HandlerServices, create_tcp_server_handler_shared};

/// Convert validated Shoes settings into the pinned `tokio_kcp` configuration.
pub(crate) fn build_kcp_config(settings: Option<&KcpSettings>) -> std::io::Result<KcpConfig> {
    let settings = settings.cloned().unwrap_or_default();
    settings.validate()?;

    let mut config = KcpConfig::default();
    match &settings.mode {
        KcpMode::Normal => {
            config.nodelay = KcpNoDelayConfig::normal();
        }
        KcpMode::Fast => {
            config.nodelay = KcpNoDelayConfig {
                nodelay: true,
                interval: 20,
                resend: 2,
                nc: true,
            };
        }
        KcpMode::Turbo => {
            config.nodelay = KcpNoDelayConfig::fastest();
        }
        KcpMode::Gaming => {
            config.nodelay = KcpNoDelayConfig::fastest();
            config.wnd_size = (1024, 1024);
        }
        KcpMode::FileTransfer => {
            config.nodelay = KcpNoDelayConfig::normal();
            config.stream = true;
            config.wnd_size = (1024, 1024);
        }
    }

    if let (Some(send), Some(recv)) = (settings.send_window, settings.recv_window) {
        config.wnd_size = (
            u16::try_from(send).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("kcp_settings.send_window exceeds u16: {send}"),
                )
            })?,
            u16::try_from(recv).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("kcp_settings.recv_window exceeds u16: {recv}"),
                )
            })?,
        );
    }
    if let Some(mtu) = settings.mtu {
        config.mtu = usize::try_from(mtu).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("kcp_settings.mtu cannot be represented: {mtu}"),
            )
        })?;
    }
    config.max_sessions = usize::try_from(settings.max_sessions).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "kcp_settings.max_sessions cannot be represented on this platform",
        )
    })?;
    Ok(config)
}

async fn run_kcp_server(
    mut listener: KcpListener,
    max_sessions: usize,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let mut tasks = crate::listener_tasks::ListenerTasks::new();
    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let (stream, addr) = match accepted {
            Ok(value) => value,
            Err(error) => {
                error!("KCP accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if tasks.len() >= max_sessions {
            debug!("KCP session limit reached: {max_sessions}");
            continue;
        }
        let Some(permit) = crate::resources::try_connection(Some(addr.ip())) else {
            continue;
        };

        let resolver = resolver.clone();
        let server_handler = server_handler.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let stream = KcpStreamWrapper::new(stream, addr);
            if let Err(error) = process_stream(stream, server_handler, resolver).await {
                error!(
                    "{}:{} finished with error: {error:?}",
                    addr.ip(),
                    addr.port()
                );
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

pub async fn start_kcp_servers(
    config: ResolvedServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ResolvedServerConfig {
        bind_location,
        kcp_settings,
        protocol,
        rules,
        sniff,
        ..
    } = config;

    println!("Starting {} KCP server at {}", &protocol, &bind_location);
    let rules = rules.into_vec();
    assert!(!rules.is_empty());

    let settings = kcp_settings.unwrap_or_default();
    let kcp_config = build_kcp_config(Some(&settings))?;
    let max_sessions = usize::try_from(settings.max_sessions).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "kcp_settings.max_sessions cannot be represented on this platform",
        )
    })?;
    let client_proxy_selector =
        Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone())?.with_sniff(sniff));

    let bind_addresses = match bind_location {
        BindLocation::Unspecified {} => {
            return Err(std::io::Error::other("KCP listener requires an address"));
        }
        BindLocation::Address(addresses) => {
            let mut result = Vec::new();
            for address in addresses.into_vec() {
                result.extend(address.to_socket_addrs()?);
            }
            result
        }
        BindLocation::Path(_) => {
            return Err(std::io::Error::other(
                "Cannot listen on path: KCP does not support Unix domain sockets",
            ));
        }
    };

    let mut seen = HashSet::new();
    let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();
    let mut services = HandlerServices::default();
    let mut listeners = Vec::new();
    for bind_address in bind_addresses {
        if bind_address.port() != 0 && !seen.insert(bind_address) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("duplicate KCP listener at {bind_address}"),
            ));
        }
        let server_handler = match handlers.entry(bind_address.ip()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                create_tcp_server_handler_shared(
                    protocol.clone(),
                    &client_proxy_selector,
                    &resolver,
                    Some(bind_address.ip()),
                    &mut services,
                )?
                .into(),
            ),
        }
        .clone();

        record_bind_attempt();
        let listener = KcpListener::bind(kcp_config, bind_address)
            .await
            .map_err(|error| {
                std::io::Error::other(format!("KCP bind at {bind_address} failed: {error}"))
            })?;
        listeners.push((listener, server_handler));
    }

    let mut handles = Vec::with_capacity(listeners.len());
    for (listener, server_handler) in listeners {
        let resolver = resolver.clone();
        handles.push(crate::network_tasks::spawn(async move {
            if let Err(error) =
                run_kcp_server(listener, max_sessions, resolver, server_handler).await
            {
                error!("KCP listener stopped: {error}");
            }
        }));
    }
    Ok(handles)
}

#[cfg(not(test))]
fn record_bind_attempt() {}

#[cfg(test)]
static KCP_BIND_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn reset_test_bind_calls() {
    KCP_BIND_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn test_bind_calls() -> usize {
    KCP_BIND_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
fn record_bind_attempt() {
    KCP_BIND_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;
    use tokio::time::{Duration, timeout};
    use tokio_kcp::KcpStream;

    fn unsolicited_packet(conv: u32) -> [u8; 24] {
        let mut packet = [0; 24];
        packet[0..4].copy_from_slice(&conv.to_le_bytes());
        packet[4] = 81; // KCP_CMD_PUSH
        packet[8..12].copy_from_slice(&0u32.to_le_bytes());
        packet
    }

    #[tokio::test]
    async fn kcp_listener_enforces_session_limit() {
        let settings = KcpSettings {
            max_sessions: 1,
            ..KcpSettings::default()
        };
        let config = build_kcp_config(Some(&settings)).unwrap();
        let mut listener = KcpListener::bind(config, "127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let malformed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        malformed.send_to(&[1, 2, 3], address).await.unwrap();

        for conv in [100, 101] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .send_to(&unsolicited_packet(conv), address)
                .await
                .unwrap();
        }

        let (first, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut active = 1;
        assert!(
            timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_err(),
            "second session exceeded the configured limit"
        );

        drop(first);
        active -= 1;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        let mut client = KcpStream::connect(&config, address).await.unwrap();
        const PING: &[u8] = b"ping";
        client.send(PING).await.unwrap();
        let (mut server, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        active += 1;

        let mut received = [0; PING.len()];
        let count = timeout(Duration::from_secs(2), server.recv(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..count], PING);
        server.send(&received[..count]).await.unwrap();
        let count = timeout(Duration::from_secs(2), client.recv(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..count], PING);

        assert_eq!(active, usize::try_from(settings.max_sessions).unwrap());
    }

    static LOG_MESSAGES: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> =
        std::sync::OnceLock::new();
    struct PayloadLogger;

    impl log::Log for PayloadLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            LOG_MESSAGES
                .get_or_init(|| std::sync::Mutex::new(Vec::new()))
                .lock()
                .unwrap()
                .push(record.args().to_string());
        }

        fn flush(&self) {}
    }

    #[tokio::test]
    async fn kcp_listener_does_not_log_payload_bytes() {
        const CHILD: &str = "SHOES_KCP_PAYLOAD_LOG_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            shoes_test_support::isolated::run_isolated(
                "kcp_server::tests::kcp_listener_does_not_log_payload_bytes",
                CHILD,
                "1",
            );
            return;
        }

        log::set_boxed_logger(Box::new(PayloadLogger)).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let config = build_kcp_config(None).unwrap();
        let mut listener = KcpListener::bind(config, "127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = unsolicited_packet(200).to_vec();
        packet.extend_from_slice(b"PAYLOAD_SECRET_SENTINEL");
        socket.send_to(&packet, address).await.unwrap();
        timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();

        let messages = LOG_MESSAGES
            .get_or_init(|| std::sync::Mutex::new(Vec::new()))
            .lock()
            .unwrap()
            .join("\n");
        assert!(
            !messages.contains("PAYLOAD_SECRET_SENTINEL"),
            "KCP payload reached logs: {messages}"
        );
        assert!(
            !messages.contains("80, 65, 89, 76"),
            "numeric KCP payload reached logs: {messages}"
        );
    }
}
