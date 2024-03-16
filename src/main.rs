use std::net::TcpListener;
use std::thread::sleep;
use std::time::Duration;

const BIP324_PROXY_PORT: u16 = 1324;

fn main() {
    // TODO: don't use unwrap() here, we want a nice error message if binding
    // fails (e.g. due to address already in use), instead of an ugly panic
    let listener = TcpListener::bind(format!("127.0.0.1:{}", BIP324_PROXY_PORT)).unwrap();
    println!("---------------------");
    println!(" BIP324 proxy server ");
    println!("---------------------");
    println!("Waiting for incoming v1 connections on 127.0.0.1:{}...", BIP324_PROXY_PORT);
    loop {
        // TODO: terminate if SIGINT (CTRL+C) is received
        // TODO: accept client connections here
        sleep(Duration::from_secs(10));
        break;
    }
}
