#!/usr/bin/env python3
import hashlib
import random
import socket
import sys
import threading

from bip324_crypto import (
    FSChaCha20,
    FSChaCha20Poly1305,
    bip324_ecdh,
    ellswift_create,
    hkdf_sha256,
)


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


def bip324_encrypt(send_l, send_p, message, aad=b''):
    enc_len = send_l.crypt(len(message).to_bytes(3, 'little'))
    enc_payload = send_p.encrypt(aad, bytes([0]) + message)
    return enc_len + enc_payload


def bip324_proxy_handler(client_sock: socket.socket) -> None:
    msgtype, payload = receive_v1_message(client_sock)
    print(f"[<] Received {msgtype.upper()} message")
    #print(f"[<] received payload {payload}")
    addr_recv = payload[20:46]
    remote_addr_ipv6 = addr_recv[8:24]
    if remote_addr_ipv6[:12] != bytes.fromhex("00000000000000000000ffff"):
        print("IPv6 is not supported yet.")
        client_sock.close()
        return
    remote_ip_bytes = remote_addr_ipv6[-4:]
    remote_ip_str = socket.inet_ntoa(remote_ip_bytes)
    remote_port = int.from_bytes(addr_recv[24:26], 'big')
    local_user_agent = payload[81:81+payload[80]].decode('ascii')
    print(f"    => Local user agent: {local_user_agent}")
    print(f"    => Remote address: {remote_ip_str}:{remote_port}")

    # connect to target node
    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_sock.connect((remote_ip_str, remote_port))
    print(f"[>] Connected to {remote_ip_str}:{remote_port}, initiating BIP324 handshake.")

    # key exchange phase
    privkey, ellswift_ours = ellswift_create()
    garbage = random.randbytes(random.randrange(4096))
    remote_sock.sendall(ellswift_ours + garbage)
    ellswift_theirs = remote_sock.recv(64)
    shared_secret = bip324_ecdh(privkey, ellswift_theirs, ellswift_ours, True)
    salt = b'bitcoin_v2_shared_secret' + bytes.fromhex("f9beb4d9")  # mainnet net magic
    keys = {}
    for name in ('initiator_L', 'initiator_P', 'responder_L', 'responder_P',
                 'garbage_terminators', 'session_id'):
        keys[name] = hkdf_sha256(salt=salt, ikm=shared_secret, info=name.encode(), length=32)
    send_garbage_terminator = keys['garbage_terminators'][:16]
    recv_garbage_terminator = keys['garbage_terminators'][16:]
    send_l = FSChaCha20(keys['initiator_L'])
    send_p = FSChaCha20Poly1305(keys['initiator_P'])
    recv_l = FSChaCha20(keys['responder_L'])
    recv_p = FSChaCha20Poly1305(keys['responder_P'])
    session_id = keys['session_id']
    keys = {}
    remote_sock.sendall(send_garbage_terminator)
    remote_sock.sendall(bip324_encrypt(send_l, send_p, b'', aad=send_garbage_terminator))
    recv_garbage_and_term = remote_sock.recv(16)
    garbterm_found = False
    for i in range(4096):
        if recv_garbage_and_term[-16:] == recv_garbage_terminator:
            garbterm_found = True
            break
        recv_garbage_and_term += remote_sock.recv(1)

    if garbterm_found:
        print("YAY, garbage terminator found!")
    else:
        print("NAY, garbage terminator not found :(:(:(")


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
        print(f"[<] New connection from {addr[0]}:{addr[1]}")
        proxy_thread = threading.Thread(target=bip324_proxy_handler, args=(client_sock,))
        proxy_thread.start()


if __name__ == '__main__':
    main()
