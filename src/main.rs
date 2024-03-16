use std::net::{TcpListener, TcpStream};

const BIP324_PROXY_PORT: u16 = 1324;

fn bip324_proxy_handler(local_socket: TcpStream) {
    println!("TODO: implement bip324_proxy_handler")
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
