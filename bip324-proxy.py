#!/usr/bin/env python3
import socket
import sys
import threading


BIP324_PROXY_PORT = 1324


def bip324_proxy_handler(client_sock: socket.socket) -> None:
    print("foobar")
    recvdata = client_sock.recv(4096)
    print(f"received: {recvdata.hex()}")


def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', BIP324_PROXY_PORT))
        sock.listen(1)  # TODO: support more than one connection
    except Exception as e:
        print(f"ERROR: Couldn't create socket: {e}")
        sys.exit(1)

    while True:
        client_sock, addr = sock.accept()
        print(f"[<] Received incoming connection from {addr[0]}:{addr[1]}")
        proxy_thread = threading.Thread(target=bip324_proxy_handler, args=(client_sock,))
        proxy_thread.start()


if __name__ == '__main__':
    main()
