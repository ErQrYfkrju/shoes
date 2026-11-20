use shoes_test_support as common;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

const KCP_TEST_TIMEOUT: Duration = Duration::from_secs(20);

async fn echo_through_socks_inbound(inbound_port: u16, echo_port: u16) -> std::io::Result<()> {
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)).await?;
    socket.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    socket.read_exact(&mut method).await?;
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo_port.to_be_bytes());
    socket.write_all(&request).await?;
    let mut reply = [0; 10];
    socket.read_exact(&mut reply).await?;
    assert_eq!(&reply[..2], &[5, 0], "CONNECT through KCP failed");

    const PAYLOAD: &[u8] = b"kcp-ping";
    socket.write_all(PAYLOAD).await?;
    let mut echoed = [0; PAYLOAD.len()];
    socket.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, PAYLOAD);
    Ok(())
}

#[tokio::test]
async fn kcp_loopback_exchanges_socks_request_response() -> Result<(), Box<dyn std::error::Error>> {
    let mut ports = common::port_helper::PortHelper::new();
    let (kcp_ip, kcp_port) = ports.get_quic_listener_port();
    let (_, inbound_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo = common::test_servers::start_tcp_stream_echo_server("127.0.0.1", echo_port).await?;

    let settings = "mode: fast, send_window: 64, recv_window: 64, mtu: 1200, max_sessions: 4";
    let config = format!(
        r#"
- address: "{kcp_ip}:{kcp_port}"
  transport: kcp
  kcp_settings: {{{settings}}}
  protocol: {{type: socks}}
- address: "127.0.0.1:{inbound_port}"
  protocol: {{type: socks}}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "{kcp_ip}:{kcp_port}"
        transport: kcp
        kcp_settings: {{{settings}}}
        protocol: {{type: socks}}
"#
    );
    let (_shoes, _shoes_config) = common::test_fixture::start_shoes_server(&config)?;

    timeout(KCP_TEST_TIMEOUT, async {
        ports.wait_for_all_ports().await?;
        echo_through_socks_inbound(inbound_port, echo_port).await
    })
    .await??;
    Ok(())
}
