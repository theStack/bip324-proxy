use bitcoin_hashes::{Hash, sha256d};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::exit;

const BIP324_PROXY_PORT: u16 = 1324;
const NET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9]; // mainnet

fn recv_v1_message(sock: &TcpStream) -> (String, Vec<u8>) {
    let mut header = vec![];
    let mut payload = vec![];

    sock.take(24).read_to_end(&mut header).unwrap();
    // TODO: proper error handling, don't panic
    assert_eq!(NET_MAGIC, header[0..4], "network magic mismatch");
    let msgtype = String::from_utf8(header[4..16].to_vec()).unwrap();
    let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap());
    sock.take(payload_len as u64).read_to_end(&mut payload).unwrap();
    let checksum = &header[20..24];
    if checksum != &sha256d::Hash::hash(&payload).as_byte_array()[..4] {
        println!("Received message with invalid checksum, closing connection.");
        exit(1);
    }
    (msgtype, payload) // TODO
}

fn bip324_proxy_handler(local_socket: TcpStream) {
    let (msgtype, payload) = recv_v1_message(&local_socket);
    println!("[<] Received {} message", msgtype.to_uppercase());
    let addr_recv = &payload[20..46];
    let remote_ipv6 = &addr_recv[8..24];
    if remote_ipv6[..12] != [0,0,0,0,0,0,0,0,0,0,0xff,0xff] {
        println!("IPv6 is not supported yet.");
        // TODO: socket closing happens automatically?
        return
    }
    let remote_ipv4 = &remote_ipv6[12..];
    let remote_ipv4_str = format!("{}.{}.{}.{}", remote_ipv4[0], remote_ipv4[1], remote_ipv4[2], remote_ipv4[3]);
    let remote_port = u16::from_be_bytes(addr_recv[24..26].try_into().unwrap());
    let local_user_agent = String::from_utf8(payload[81..81+payload[80] as usize].to_vec()).unwrap();
    println!("    => Local user agent: {}", local_user_agent);
    println!("    => Remote address: {}:{}", remote_ipv4_str, remote_port);

    println!("TODO: implement rest of bip324_proxy_handler")
}

fn main() {
    // TODO: don't use unwrap() here, we want a nice error message if binding
    // fails (e.g. due to address already in use), instead of an ugly panic
    let listener = TcpListener::bind(format!("127.0.0.1:{}", BIP324_PROXY_PORT)).unwrap();
    println!("---------------------");
    println!(" BIP324 proxy server ");
    println!("---------------------");
    println!("Waiting for incoming v1 connections on 127.0.0.1:{}...", BIP324_PROXY_PORT);

    // TODO: terminate if SIGINT (CTRL+C) is received
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        println!("[<] New connection from {}", stream.peer_addr().unwrap());
        // TODO: start the handler in a new thread
        bip324_proxy_handler(stream);
    }
}
