#!/usr/bin/env python3
import hashlib
import socket
import sys
import threading

from bip324_crypto import ellswift_create, bip324_ecdh


BIP324_PROXY_PORT = 1324


def sha256(s):
    return hashlib.sha256(s).digest()


def receive_v1_message(sock):
    header = sock.recv(24)
    if not header:
        print("Connection closed (expected header).")
        sys.exit(3)
    assert header[0:4] == bytes.fromhex("f9beb4d9")  # mainnet net magic
    msgtype = header[4:16].decode('ascii').rstrip('\x00')
    length = int.from_bytes(header[16:20], 'little')
    payload = b''
    bytes_left = length
    while bytes_left > 0:
        bytes_to_read = min(bytes_left, 4096)
        payload_part = sock.recv(bytes_to_read)
        if not payload_part:
            print("Connection closed (expected payload).")
            sys.exit(4)
        payload += payload_part
        bytes_left -= len(payload_part)
    assert length == len(payload)
    checksum = header[20:24]
    if checksum != sha256(sha256(payload))[:4]:
        print("Received message with invalid checksum, closing connection.")
        sys.exit(5)
    return msgtype, payload


def bip324_proxy_handler(client_sock: socket.socket) -> None:
    msgtype, payload = receive_v1_message(client_sock)
    print(f"[<] received msgtype {msgtype}")
    print(f"[<] received payload {payload}")


def main():
    # bip324 ecdh sanity check
    privkey, pubkey = ellswift_create()
    privkey_other, pubkey_other = ellswift_create()
    shared_secret1 = bip324_ecdh(privkey, pubkey_other, pubkey, True)
    shared_secret2 = bip324_ecdh(privkey_other, pubkey, pubkey_other, False)
    assert shared_secret1 == shared_secret2

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
