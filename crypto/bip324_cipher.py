#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only implementation of ChaCha20 Poly1305 AEAD Construction in RFC 8439 and FSChaCha20Poly1305 for BIP 324

It is designed for ease of understanding, not performance.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do not use for
anything but tests.
"""
CHACHA20_INDICES = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)
)

CHACHA20_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
REKEY_INTERVAL = 224 # packets


def rotl32(v, bits):
    """Rotate the 32-bit value v left by bits bits."""
    bits %= 32  # Make sure the term below does not throw an exception
    return ((v << bits) & 0xffffffff) | (v >> (32 - bits))


def chacha20_doubleround(s):
    """Apply a ChaCha20 double round to 16-element state array s.
    See https://cr.yp.to/chacha/chacha-20080128.pdf and https://tools.ietf.org/html/rfc8439
    """
    for a, b, c, d in CHACHA20_INDICES:
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 7)


def chacha20_block(key, nonce, cnt):
    """Compute the 64-byte output of the ChaCha20 block function.
    Takes as input a 32-byte key, 12-byte nonce, and 32-bit integer counter.
    """
    # Initial state.
    init = [0] * 16
    init[:4] = CHACHA20_CONSTANTS[:4]
    init[4:12] = [int.from_bytes(key[i:i+4], 'little') for i in range(0, 32, 4)]
    init[12] = cnt
    init[13:16] = [int.from_bytes(nonce[i:i+4], 'little') for i in range(0, 12, 4)]
    # Perform 20 rounds.
    state = list(init)
    for _ in range(10):
        chacha20_doubleround(state)
    # Add initial values back into state.
    for i in range(16):
        state[i] = (state[i] + init[i]) & 0xffffffff
    # Produce byte output
    return b''.join(state[i].to_bytes(4, 'little') for i in range(16))


class FSChaCha20:
    """Rekeying wrapper stream cipher around ChaCha20."""
    def __init__(self, initial_key, rekey_interval=REKEY_INTERVAL):
        self._key = initial_key
        self._rekey_interval = rekey_interval
        self._block_counter = 0
        self._chunk_counter = 0
        self._keystream = b''

    def _get_keystream_bytes(self, nbytes):
        while len(self._keystream) < nbytes:
            nonce = ((0).to_bytes(4, 'little') + (self._chunk_counter // self._rekey_interval).to_bytes(8, 'little'))
            self._keystream += chacha20_block(self._key, nonce, self._block_counter)
            self._block_counter += 1
        ret = self._keystream[:nbytes]
        self._keystream = self._keystream[nbytes:]
        return ret

    def crypt(self, chunk):
        ks = self._get_keystream_bytes(len(chunk))
        ret = bytes([ks[i] ^ chunk[i] for i in range(len(chunk))])
        if ((self._chunk_counter + 1) % self._rekey_interval) == 0:
            self._key = self._get_keystream_bytes(32)
            self._block_counter = 0
            self._keystream = b''
        self._chunk_counter += 1
        return ret


class Poly1305:
    """Class representing a running poly1305 computation."""
    MODULUS = 2**130 - 5

    def __init__(self, key):
        self.r = int.from_bytes(key[:16], 'little') & 0xffffffc0ffffffc0ffffffc0fffffff
        self.s = int.from_bytes(key[16:], 'little')

    def tag(self, data):
        """Compute the poly1305 tag."""
        acc, length = 0, len(data)
        for i in range((length + 15) // 16):
            chunk = data[i * 16:min(length, (i + 1) * 16)]
            val = int.from_bytes(chunk, 'little') + 256**len(chunk)
            acc = (self.r * (acc + val)) % Poly1305.MODULUS
        return ((acc + self.s) & 0xffffffffffffffffffffffffffffffff).to_bytes(16, 'little')


def pad16(x):
    if len(x) % 16 == 0:
        return b''
    return b'\x00' * (16 - (len(x) % 16))


def aead_chacha20_poly1305_encrypt(key, nonce, aad, plaintext):
    """Encrypt a plaintext using ChaCha20Poly1305."""
    ret = bytearray()
    msg_len = len(plaintext)
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(plaintext[j + 64 * i] ^ keystream[j])
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    mac_data = aad + pad16(aad)
    mac_data += ret + pad16(ret)
    mac_data += len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little')
    ret += poly1305.tag(mac_data)
    return bytes(ret)


def aead_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext):
    """Decrypt a ChaCha20Poly1305 ciphertext."""
    if len(ciphertext) < 16:
        return None
    msg_len = len(ciphertext) - 16
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    mac_data = aad + pad16(aad)
    mac_data += ciphertext[:-16] + pad16(ciphertext[:-16])
    mac_data += len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little')
    if ciphertext[-16:] != poly1305.tag(mac_data):
        return None
    ret = bytearray()
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(ciphertext[j + 64 * i] ^ keystream[j])
    return bytes(ret)


class FSChaCha20Poly1305:
    """Rekeying wrapper AEAD around ChaCha20Poly1305."""
    def __init__(self, initial_key):
        self._key = initial_key
        self._packet_counter = 0

    def _crypt(self, aad, text, is_decrypt):
        nonce = ((self._packet_counter % REKEY_INTERVAL).to_bytes(4, 'little') +
                 (self._packet_counter // REKEY_INTERVAL).to_bytes(8, 'little'))
        if is_decrypt:
            ret = aead_chacha20_poly1305_decrypt(self._key, nonce, aad, text)
        else:
            ret = aead_chacha20_poly1305_encrypt(self._key, nonce, aad, text)
        if (self._packet_counter + 1) % REKEY_INTERVAL == 0:
            rekey_nonce = b"\xFF\xFF\xFF\xFF" + nonce[4:]
            self._key = aead_chacha20_poly1305_encrypt(self._key, rekey_nonce, b"", b"\x00" * 32)[:32]
        self._packet_counter += 1
        return ret

    def decrypt(self, aad, ciphertext):
        return self._crypt(aad, ciphertext, True)

    def encrypt(self, aad, plaintext):
        return self._crypt(aad, plaintext, False)
