use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_kcp::KcpStream;

use crate::async_stream::{AsyncPing, AsyncStream};

/// Shoes stream adapter for the pinned `tokio_kcp` stream.
///
/// Auto trait implementations are used instead of the old `unsafe impl Sync`.
pub struct KcpStreamWrapper {
    stream: KcpStream,
    peer: SocketAddr,
}

impl KcpStreamWrapper {
    pub fn new(stream: KcpStream, peer: SocketAddr) -> Self {
        Self { stream, peer }
    }
}

impl AsyncRead for KcpStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for KcpStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl AsyncPing for KcpStreamWrapper {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for KcpStreamWrapper {
    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }
}
