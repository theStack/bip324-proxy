#!/usr/bin/env python3
import random
from select import select
import socket
import sys
import threading

from bip324_crypto import *


BIP324_PROXY_PORT = 1324
BIP324_SHORTID_MSGTYPES = [
    "addr", "block", "blocktxn", "cmpctblock", "feefilter", "filteradd", "filterclear", "filterload",
    "getblocks", "getblocktxn", "getdata", "getheaders", "headers", "inv", "mempool", "merkleblock",
    "notfound", "ping", "pong", "sendcmpct", "tx", "getcfilters", "cfilter", "getcfheaders", "cfheaders",
    "getcfcheckpt", "cfcheckpt", "addrv2",
]
NET_MAGIC = bytes.fromhex("f9beb4d9")  # mainnet
V1_PREFIX = NET_MAGIC + b"version\x00\x00\x00\x00\x00"
V1_FALLBACK_ALLOWED = False  # only allow v2 connections


class ConnClosedException(Exception):
    pass

def recvall(sock, length):
    msg = b''
    bytes_left = length
    while bytes_left > 0:
        part = sock.recv(min(bytes_left, 16384))
        if not part:
            raise ConnClosedException()
        msg += part
        bytes_left -= len(part)
    return msg


def send_v1_message(sock, msgtype, payload):
    msg = NET_MAGIC
    msg += msgtype.encode() + bytes([0]*(12 - len(msgtype)))
    msg += len(payload).to_bytes(4, 'little') + sha256(sha256(payload))[:4] + payload
    sock.sendall(msg)

def recv_v1_message(sock):
    header = recvall(sock, 24)
    assert header[0:4] == NET_MAGIC
    msgtype = header[4:16].decode('ascii').rstrip('\x00')
    length = int.from_bytes(header[16:20], 'little')
    payload = recvall(sock, length)
    assert length == len(payload)
    checksum = header[20:24]
    if checksum != sha256(sha256(payload))[:4]:
        print("Received message with invalid checksum, closing connection.")
        sys.exit(5)
    return msgtype, payload


def bip324_send(sock, send_l, send_p, message, aad=b''):
    enc_len = send_l.crypt(len(message).to_bytes(3, 'little'))
    enc_payload = send_p.encrypt(aad, bytes([0]) + message)
    sock.sendall(enc_len + enc_payload)

def bip324_recv(sock, recv_l, recv_p, aad=b''):
    length = int.from_bytes(recv_l.crypt(recvall(sock, 3)), 'little')
    enc_stuff = recvall(sock, 1 + length + 16)
    header_contents_expansion = recv_p.decrypt(aad, enc_stuff)
    assert header_contents_expansion is not None
    return header_contents_expansion[1:length+1]


def send_v2_message(sock, send_l, send_p, msgtype, payload):
    if msgtype in BIP324_SHORTID_MSGTYPES:
        complete_msg = bytes([BIP324_SHORTID_MSGTYPES.index(msgtype)+1]) + payload
    else:
        complete_msg = bytes([0]) + msgtype.encode() + bytes([0]*(12 - len(msgtype))) + payload
    bip324_send(sock, send_l, send_p, complete_msg)

def recv_v2_message(sock, recv_l, recv_p):
    complete_msg = bip324_recv(sock, recv_l, recv_p)
    if 1 <= complete_msg[0] <= len(BIP324_SHORTID_MSGTYPES):
        return BIP324_SHORTID_MSGTYPES[complete_msg[0]-1], complete_msg[1:]
    else:
        return complete_msg[1:13].rstrip(bytes([0])).decode(), complete_msg[13:]


def log_recv(direction_tag, msgtype, payload):
    payload_str = payload.hex() if len(payload) <= 16 else f"{payload[:16].hex()}..."
    print(f"[{direction_tag}] Received msgtype {msgtype}, payload {payload_str} ({len(payload)} bytes)")


def bip324_proxy_handler(local_socket):
    # peek into receive buffer byte for byte to detect early if the first
    # incoming message is not a bitcoin p2p v1 message; in that case we can't
    # do anything (we wouldn't know the remote destination to send data to) and
    # have to close the local conncection
    peeked_prefix = b''
    while len(peeked_prefix) < len(V1_PREFIX):
        peeked_prefix = local_socket.recv(len(peeked_prefix)+1, socket.MSG_PEEK)
        expected_prefix = V1_PREFIX[:len(peeked_prefix)]
        if peeked_prefix != expected_prefix:
            print(f"V1 prefix mismatch after {len(peeked_prefix)} bytes " \
                  f"(expected {expected_prefix.hex()} got {peeked_prefix.hex()}), close connection.")
            local_socket.close()
            return

    msgtype, payload = recv_v1_message(local_socket)
    print(f"[<] Received {msgtype.upper()} message")
    addr_recv = payload[20:46]
    remote_addr_ipv6 = addr_recv[8:24]
    if remote_addr_ipv6[:12] != bytes.fromhex("00000000000000000000ffff"):
        print("IPv6 is not supported yet.")
        local_socket.close()
        return
    remote_ip_bytes = remote_addr_ipv6[-4:]
    remote_ip_str = socket.inet_ntoa(remote_ip_bytes)
    remote_port = int.from_bytes(addr_recv[24:26], 'big')
    local_user_agent = payload[81:81+payload[80]].decode('ascii')
    print(f"    => Local user agent: {local_user_agent}")
    print(f"    => Remote address: {remote_ip_str}:{remote_port}")

    # connect to target node
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_ip_str, remote_port))
    print(f"[>] Connected to {remote_ip_str}:{remote_port}, initiating BIP324 handshake.")

    # key exchange phase
    privkey, ellswift_ours = ellswift_create()
    garbage = random.randbytes(random.randrange(4096))
    remote_socket.sendall(ellswift_ours + garbage)
    v1_fallback = False
    try:
        ellswift_theirs = recvall(remote_socket, 64)
    except (ConnClosedException, ConnectionResetError):
        print(f"[!] Peer {remote_ip_str}:{remote_port} closed connection. ", end='')
        if V1_FALLBACK_ALLOWED:
            print("Reconnect and pass through everything in v1...", end='')
            v1_fallback = True
        else:
            print("Closing (we only allow v2 connections!).")
            local_socket.close()
            return
        print()
    if v1_fallback:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((remote_ip_str, remote_port))
        print(f"[>] Re-connected to {remote_ip_str}:{remote_port}, passing through v1 VERSION message.")
        send_v1_message(remote_socket, msgtype, payload)
        while True:
            r, _, _ = select([local_socket, remote_socket], [], [])
            if local_socket in r:
                msgtype, payload = recv_v1_message(local_socket)
                send_v1_message(remote_socket, msgtype, payload)
                log_recv('<-- (v1)', msgtype, payload)
            if remote_socket in r:
                msgtype, payload = recv_v1_message(remote_socket)
                send_v1_message(local_socket, msgtype, payload)
                log_recv('--> (v1)', msgtype, payload)
        return
    shared_secret = bip324_ecdh(privkey, ellswift_theirs, ellswift_ours, True)
    salt = b'bitcoin_v2_shared_secret' + NET_MAGIC
    keys = {}
    for name in ('initiator_L', 'initiator_P', 'responder_L', 'responder_P',
                 'garbage_terminators', 'session_id'):
        keys[name] = hkdf_sha256(salt=salt, ikm=shared_secret, info=name.encode(), length=32)
    send_garbage_terminator = keys['garbage_terminators'][:16]
    recv_garbage_terminator = keys['garbage_terminators'][16:]
    send_l, send_p = FSChaCha20(keys['initiator_L']), FSChaCha20Poly1305(keys['initiator_P'])
    recv_l, recv_p = FSChaCha20(keys['responder_L']), FSChaCha20Poly1305(keys['responder_P'])
    session_id = keys['session_id']
    remote_socket.sendall(send_garbage_terminator)
    bip324_send(remote_socket, send_l, send_p, b'', aad=garbage)
    recv_garbage_and_term = recvall(remote_socket, 16)
    garbterm_found = False
    for i in range(4096):
        if recv_garbage_and_term[-16:] == recv_garbage_terminator:
            garbterm_found = True
            break
        recv_garbage_and_term += recvall(remote_socket, 1)

    if garbterm_found:
        print(f"YAY, garbage terminator found! (garb+garbterm len: {len(recv_garbage_and_term)})")
    else:
        print("NAY, garbage terminator not found :(:(:(")
        print("[-] Proxy session finished")
        return
    bip324_version = bip324_recv(remote_socket, recv_l, recv_p, aad=recv_garbage_and_term[:-16])
    assert bip324_version == b''
    print("[-] Handshake phase finished.")
    with open('./v2_connections.log', 'a') as f:
        f.write(f'v2 connection established from local client "{local_user_agent}" to {remote_ip_str}:{remote_port}.\n')
        f.write(f'    bip324 session id: {session_id.hex()}\n\n')
    send_v2_message(remote_socket, send_l, send_p, msgtype, payload)
    print(f"[<] Sent version message to remote peer.")

    while True:
        r, _, _ = select([local_socket, remote_socket], [], [])
        if local_socket in r:   # [local] v1 ---> v2 [remote]
            msgtype, payload = recv_v1_message(local_socket)
            send_v2_message(remote_socket, send_l, send_p, msgtype, payload)
            log_recv('-->', msgtype, payload)
        if remote_socket in r:  # [local] v1 <--- v2 [remote]
            msgtype, payload = recv_v2_message(remote_socket, recv_l, recv_p)
            send_v1_message(local_socket, msgtype, payload)
            log_recv('<--', msgtype, payload)


def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', BIP324_PROXY_PORT))
        sock.listen(5)
    except Exception as e:
        print(f"ERROR: Couldn't create socket: {e}")
        sys.exit(1)

    print( "---------------------")
    print(f" BIP324 proxy server ")
    print( "---------------------")
    print(f"Waiting for incoming v1 connections on 127.0.0.1:{BIP324_PROXY_PORT}...")
    while True:
        local_socket, addr = sock.accept()
        print(f"[<] New connection from {addr[0]}:{addr[1]}")
        proxy_thread = threading.Thread(target=bip324_proxy_handler, args=(local_socket,))
        proxy_thread.start()


if __name__ == '__main__':
    main()
