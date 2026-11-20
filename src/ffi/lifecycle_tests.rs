use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

fn vpn_config(fd: i32) -> String {
    format!(
        r#"- device_fd: {fd}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "127.0.0.1:9"
          transport: quic
          quic_settings:
            verify: false
          protocol:
            type: socks
"#
    )
}

fn counting_protector(
    calls: Arc<AtomicUsize>,
    entered: mpsc::Sender<()>,
) -> Arc<dyn crate::tun::SocketProtector> {
    Arc::new(crate::tun::FnSocketProtector::new(move |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        entered.send(()).unwrap();
        Ok(())
    }))
}

fn assert_fd_open(fd: i32) {
    // SAFETY: this only queries descriptor flags and never modifies fd state.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(
        flags >= 0,
        "native service closed the Android-owned fd {fd}"
    );
}

#[test]
fn native_stop_preserves_android_owned_fd_and_replaces_protector() {
    let (_peer, tun) = UnixDatagram::pair().unwrap();
    let fd = tun.as_raw_fd();
    let first_calls = Arc::new(AtomicUsize::new(0));
    let (first_tx, first_rx) = mpsc::channel();
    let (running, _) = tests::start_test_service(
        vpn_config(fd),
        counting_protector(first_calls.clone(), first_tx),
    );
    first_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert!(running.load(Ordering::SeqCst));

    assert!(stop_service());
    assert!(!running.load(Ordering::SeqCst));
    assert_fd_open(fd);
    let first_count = first_calls.load(Ordering::SeqCst);
    assert!(first_count > 0);

    let (_second_peer, second_tun) = UnixDatagram::pair().unwrap();
    let second_fd = second_tun.as_raw_fd();
    let second_calls = Arc::new(AtomicUsize::new(0));
    let (second_tx, second_rx) = mpsc::channel();
    let (second_running, _) = tests::start_test_service(
        vpn_config(second_fd),
        counting_protector(second_calls.clone(), second_tx),
    );
    second_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert!(second_running.load(Ordering::SeqCst));
    assert!(second_calls.load(Ordering::SeqCst) > 0);
    assert_eq!(first_calls.load(Ordering::SeqCst), first_count);

    assert!(stop_service());
    assert!(!second_running.load(Ordering::SeqCst));
    assert_fd_open(fd);
    assert_fd_open(second_fd);
}
