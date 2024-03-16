const BIP324_PROXY_PORT: u16 = 1324;

fn main() {
    println!("---------------------");
    println!(" BIP324 proxy server ");
    println!("---------------------");
    println!("Waiting for incoming v1 connections on 127.0.0.1:{}...", BIP324_PROXY_PORT);
}
