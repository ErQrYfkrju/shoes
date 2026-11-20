use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn wait_for_tcp(address: std::net::SocketAddr) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(address).await {
            Ok(_) => return Ok(()),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn echo_through_socks(proxy: std::net::SocketAddr, echo_port: u16) -> std::io::Result<()> {
    let mut socket = TcpStream::connect(proxy).await?;
    socket.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    socket.read_exact(&mut method).await?;
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo_port.to_be_bytes());
    socket.write_all(&request).await?;
    let mut reply = [0; 10];
    socket.read_exact(&mut reply).await?;
    assert_eq!(&reply[..2], &[5, 0]);

    socket.write_all(b"ping").await?;
    let mut echoed = [0; 4];
    socket.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    Ok(())
}

fn start_test_proxy_service(
    config: String,
) -> (Arc<AtomicBool>, Arc<AtomicUsize>, tokio::task::AbortHandle) {
    let _lifecycle = SERVICE_LIFECYCLE.lock();
    let protect_calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = protect_calls.clone();
    crate::tun::set_global_socket_protector(Arc::new(crate::tun::FnSocketProtector::new(
        move |_| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )));
    // Match the Android null-callback path: replace stale VPN protection with a no-op.
    crate::tun::set_global_socket_protector(Arc::new(crate::tun::NoOpSocketProtector));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(AtomicBool::new(true));
    let task = spawn_proxy_service(&runtime, config, shutdown_rx, running.clone());
    let abort_handle = task.abort_handle();
    *TUN_SERVICE
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock() = Some(TunServiceHandle {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        running: running.clone(),
        task,
    });
    (running, protect_calls, abort_handle)
}

#[tokio::test]
async fn proxy_mode_serves_server_without_tun() {
    const CHILD: &str = "SHOES_FFI_PROXY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ffi::common::proxy_tests::proxy_mode_serves_server_without_tun",
            CHILD,
            "1",
        );
        return;
    }

    let mut ports = shoes_test_support::port_helper::PortHelper::new();
    let (_, proxy_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo =
        shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", echo_port)
            .await
            .unwrap();
    let proxy_address: std::net::SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    let config = format!(
        r#"- address: "127.0.0.1:{proxy_port}"
  protocol: {{type: socks}}
"#
    );
    let (running, protect_calls, _task) = start_test_proxy_service(config);
    wait_for_tcp(proxy_address).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        echo_through_socks(proxy_address, echo_port),
    )
    .await
    .unwrap()
    .unwrap();

    let stopped = std::thread::spawn(stop_service).join().unwrap();
    assert!(stopped);
    assert!(!running.load(Ordering::SeqCst));
    assert!(!is_service_running());
    assert_eq!(protect_calls.load(Ordering::SeqCst), 0);
}
