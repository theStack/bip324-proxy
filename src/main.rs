use std::io::Read;
use std::net::{TcpListener, TcpStream};

const BIP324_PROXY_PORT: u16 = 1324;
const NET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9]; // mainnet

fn recv_v1_message(sock: &TcpStream) -> (String, Vec<u8>) {
    let mut buf: Vec<u8> = vec![];
    let mut payload: Vec<u8> = vec![];

    sock.take(24).read_to_end(&mut buf).unwrap();
    // TODO: proper error handling, don't panic
    assert_eq!(NET_MAGIC, buf[0..4], "network magic mismatch");
    let msgtype = String::from_utf8(buf[4..16].to_vec()).unwrap();
    let payload_len = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    sock.take(payload_len as u64).read_to_end(&mut payload).unwrap();
    println!("TODO: verify v1 payload checksum");
    (msgtype, payload) // TODO
}

fn bip324_proxy_handler(local_socket: TcpStream) {
    let (msgtype, payload) = recv_v1_message(&local_socket);
    println!("received msgtype = {}, payload = {:02x?}", msgtype, payload);
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
