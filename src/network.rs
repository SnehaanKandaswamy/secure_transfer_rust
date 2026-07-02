use anyhow::Result;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};

use crate::config::{DATA_PORT, HOST, KEY_PORT};

/// Receive exactly `size` bytes from a TCP stream.
pub fn recv_exact(stream: &mut TcpStream, size: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Send all bytes over TCP.
pub fn send_all(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(data)?;
    Ok(())
}

/// Create sender UDP socket.
pub fn create_udp_sender() -> Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    Ok(socket)
}

/// Create receiver UDP socket.
pub fn create_udp_receiver() -> Result<UdpSocket> {
    let socket = UdpSocket::bind((HOST, DATA_PORT))?;
    Ok(socket)
}

/// Create TCP listener.
pub fn create_key_server() -> Result<TcpListener> {
    Ok(TcpListener::bind((HOST, KEY_PORT))?)
}

/// Connect to TCP server.
pub fn connect_key_server() -> Result<TcpStream> {
    Ok(TcpStream::connect((HOST, KEY_PORT))?)
}