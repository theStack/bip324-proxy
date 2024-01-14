#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only single-module implementation of BIP 324

It is designed for ease of understanding, not performance.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do not use for
anything but tests.
"""
import hashlib
import hmac
import random


#################
### secp256k1 ###
#################
class FE:
    """Objects of this class represent elements of the field GF(2**256 - 2**32 - 977).

    They are represented internally in numerator / denominator form, in order to delay inversions.
    """

    # The size of the field (also its modulus and characteristic).
    SIZE = 2**256 - 2**32 - 977

    def __init__(self, a=0, b=1):
        """Initialize a field element a/b; both a and b can be ints or field elements."""
        if isinstance(a, FE):
            num = a._num
            den = a._den
        else:
            num = a % FE.SIZE
            den = 1
        if isinstance(b, FE):
            den = (den * b._num) % FE.SIZE
            num = (num * b._den) % FE.SIZE
        else:
            den = (den * b) % FE.SIZE
        assert den != 0
        if num == 0:
            den = 1
        self._num = num
        self._den = den

    def __add__(self, a):
        """Compute the sum of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._den + self._den * a._num, self._den * a._den)
        return FE(self._num + self._den * a, self._den)

    def __radd__(self, a):
        """Compute the sum of an integer and a field element."""
        return FE(a) + self

    def __sub__(self, a):
        """Compute the difference of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._den - self._den * a._num, self._den * a._den)
        return FE(self._num - self._den * a, self._den)

    def __rsub__(self, a):
        """Compute the difference of an integer and a field element."""
        return FE(a) - self

    def __mul__(self, a):
        """Compute the product of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._num, self._den * a._den)
        return FE(self._num * a, self._den)

    def __rmul__(self, a):
        """Compute the product of an integer with a field element."""
        return FE(a) * self

    def __truediv__(self, a):
        """Compute the ratio of two field elements (second may be int)."""
        return FE(self, a)

    def __pow__(self, a):
        """Raise a field element to an integer power."""
        return FE(pow(self._num, a, FE.SIZE), pow(self._den, a, FE.SIZE))

    def __neg__(self):
        """Negate a field element."""
        return FE(-self._num, self._den)

    def __int__(self):
        """Convert a field element to an integer in range 0..p-1. The result is cached."""
        if self._den != 1:
            self._num = (self._num * pow(self._den, -1, FE.SIZE)) % FE.SIZE
            self._den = 1
        return self._num

    def sqrt(self):
        """Compute the square root of a field element if it exists (None otherwise).

        Due to the fact that our modulus is of the form (p % 4) == 3, the Tonelli-Shanks
        algorithm (https://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm) is simply
        raising the argument to the power (p + 1) / 4.

        To see why: (p-1) % 2 = 0, so 2 divides the order of the multiplicative group,
        and thus only half of the non-zero field elements are squares. An element a is
        a (nonzero) square when Euler's criterion, a^((p-1)/2) = 1 (mod p), holds. We're
        looking for x such that x^2 = a (mod p). Given a^((p-1)/2) = 1, that is equivalent
        to x^2 = a^(1 + (p-1)/2) mod p. As (1 + (p-1)/2) is even, this is equivalent to
        x = a^((1 + (p-1)/2)/2) mod p, or x = a^((p+1)/4) mod p."""
        v = int(self)
        s = pow(v, (FE.SIZE + 1) // 4, FE.SIZE)
        if s**2 % FE.SIZE == v:
            return FE(s)
        return None

    def is_square(self):
        """Determine if this field element has a square root."""
        # A more efficient algorithm is possible here (Jacobi symbol).
        return self.sqrt() is not None

    def is_even(self):
        """Determine whether this field element, represented as integer in 0..p-1, is even."""
        return int(self) & 1 == 0

    def __eq__(self, a):
        """Check whether two field elements are equal (second may be an int)."""
        if isinstance(a, FE):
            return (self._num * a._den - self._den * a._num) % FE.SIZE == 0
        return (self._num - self._den * a) % FE.SIZE == 0

    def to_bytes(self):
        """Convert a field element to a 32-byte array (BE byte order)."""
        return int(self).to_bytes(32, 'big')

    @staticmethod
    def from_bytes(b):
        """Convert a 32-byte array to a field element (BE byte order, no overflow allowed)."""
        v = int.from_bytes(b, 'big')
        if v >= FE.SIZE:
            return None
        return FE(v)

    def __str__(self):
        """Convert this field element to a 64 character hex string."""
        return f"{int(self):064x}"

    def __repr__(self):
        """Get a string representation of this field element."""
        return f"FE(0x{int(self):x})"


class GE:
    """Objects of this class represent secp256k1 group elements (curve points or infinity)

    Normal points on the curve have fields:
    * x: the x coordinate (a field element)
    * y: the y coordinate (a field element, satisfying y^2 = x^3 + 7)
    * infinity: False

    The point at infinity has field:
    * infinity: True
    """

    # Order of the group (number of points on the curve, plus 1 for infinity)
    ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # Number of valid distinct x coordinates on the curve.
    ORDER_HALF = ORDER // 2

    def __init__(self, x=None, y=None):
        """Initialize a group element with specified x and y coordinates, or infinity."""
        if x is None:
            # Initialize as infinity.
            assert y is None
            self.infinity = True
        else:
            # Initialize as point on the curve (and check that it is).
            fx = FE(x)
            fy = FE(y)
            assert fy**2 == fx**3 + 7
            self.infinity = False
            self.x = fx
            self.y = fy

    def __add__(self, a):
        """Add two group elements together."""
        # Deal with infinity: a + infinity == infinity + a == a.
        if self.infinity:
            return a
        if a.infinity:
            return self
        if self.x == a.x:
            if self.y != a.y:
                # A point added to its own negation is infinity.
                assert self.y + a.y == 0
                return GE()
            else:
                # For identical inputs, use the tangent (doubling formula).
                lam = (3 * self.x**2) / (2 * self.y)
        else:
            # For distinct inputs, use the line through both points (adding formula).
            lam = (self.y - a.y) / (self.x - a.x)
        # Determine point opposite to the intersection of that line with the curve.
        x = lam**2 - (self.x + a.x)
        y = lam * (self.x - x) - self.y
        return GE(x, y)

    @staticmethod
    def mul(*aps):
        """Compute a (batch) scalar group element multiplication.

        GE.mul((a1, p1), (a2, p2), (a3, p3)) is identical to a1*p1 + a2*p2 + a3*p3,
        but more efficient."""
        # Reduce all the scalars modulo order first (so we can deal with negatives etc).
        naps = [(a % GE.ORDER, p) for a, p in aps]
        # Start with point at infinity.
        r = GE()
        # Iterate over all bit positions, from high to low.
        for i in range(255, -1, -1):
            # Double what we have so far.
            r = r + r
            # Add then add the points for which the corresponding scalar bit is set.
            for (a, p) in naps:
                if (a >> i) & 1:
                    r += p
        return r

    def __rmul__(self, a):
        """Multiply an integer with a group element."""
        return GE.mul((a, self))

    def __neg__(self):
        """Compute the negation of a group element."""
        if self.infinity:
            return self
        return GE(self.x, -self.y)

    @staticmethod
    def lift_x(x):
        """Return group element with specified field element as x coordinate (and even y)."""
        y = (FE(x)**3 + 7).sqrt()
        if y is None:
            return None
        if not y.is_even():
            y = -y
        return GE(x, y)

    @staticmethod
    def is_valid_x(x):
        """Determine whether the provided field element is a valid X coordinate."""
        return (FE(x)**3 + 7).is_square()

    def __str__(self):
        """Convert this group element to a string."""
        if self.infinity:
            return "(inf)"
        return f"({self.x},{self.y})"

    def __repr__(self):
        """Get a string representation for this group element."""
        if self.infinity:
            return "GE()"
        return f"GE(0x{int(self.x):x},0x{int(self.y):x})"

# The secp256k1 generator point
G = GE.lift_x(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)


################
### ellswift ###
################
# Precomputed constant square root of -3 (mod p).
MINUS_3_SQRT = FE(-3).sqrt()

def xswiftec(u, t):
    """Decode field elements (u, t) to an X coordinate on the curve."""
    if u == 0:
        u = FE(1)
    if t == 0:
        t = FE(1)
    if u**3 + t**2 + 7 == 0:
        t = 2 * t
    X = (u**3 + 7 - t**2) / (2 * t)
    Y = (X + t) / (MINUS_3_SQRT * u)
    for x in (u + 4 * Y**2, (-X / Y - u) / 2, (X / Y - u) / 2):
        if GE.is_valid_x(x):
            return x
    assert False

def xswiftec_inv(x, u, case):
    """Given x and u, find t such that xswiftec(u, t) = x, or return None.

    Case selects which of the up to 8 results to return."""

    if case & 2 == 0:
        if GE.is_valid_x(-x - u):
            return None
        v = x
        s = -(u**3 + 7) / (u**2 + u*v + v**2)
    else:
        s = x - u
        if s == 0:
            return None
        r = (-s * (4 * (u**3 + 7) + 3 * s * u**2)).sqrt()
        if r is None:
            return None
        if case & 1 and r == 0:
            return None
        v = (-u + r / s) / 2
    w = s.sqrt()
    if w is None:
        return None
    if case & 5 == 0:
        return -w * (u * (1 - MINUS_3_SQRT) / 2 + v)
    if case & 5 == 1:
        return w * (u * (1 + MINUS_3_SQRT) / 2 + v)
    if case & 5 == 4:
        return w * (u * (1 - MINUS_3_SQRT) / 2 + v)
    if case & 5 == 5:
        return -w * (u * (1 + MINUS_3_SQRT) / 2 + v)

def xelligatorswift(x):
    """Given a field element X on the curve, find (u, t) that encode them."""
    assert GE.is_valid_x(x)
    while True:
        u = FE(random.randrange(1, FE.SIZE))
        case = random.randrange(0, 8)
        t = xswiftec_inv(x, u, case)
        if t is not None:
            return u, t

def ellswift_create():
    """Generate a (privkey, ellswift_pubkey) pair."""
    priv = random.randrange(1, GE.ORDER)
    u, t = xelligatorswift((priv * G).x)
    return priv.to_bytes(32, 'big'), u.to_bytes() + t.to_bytes()

def ellswift_ecdh_xonly(pubkey_theirs, privkey):
    """Compute X coordinate of shared ECDH point between ellswift pubkey and privkey."""
    u = FE(int.from_bytes(pubkey_theirs[:32], 'big'))
    t = FE(int.from_bytes(pubkey_theirs[32:], 'big'))
    d = int.from_bytes(privkey, 'big')
    return (d * GE.lift_x(xswiftec(u, t))).x.to_bytes()


############
### hkdf ###
############
def hmac_sha256(key, data):
    """Compute HMAC-SHA256 from specified byte arrays key and data."""
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(length, ikm, salt, info):
    """Derive a key using HKDF-SHA256."""
    if len(salt) == 0:
        salt = bytes([0] * 32)
    prk = hmac_sha256(salt, ikm)
    t = b""
    okm = b""
    for i in range((length + 32 - 1) // 32):
        t = hmac_sha256(prk, t + info + bytes([i + 1]))
        okm += t
    return okm[:length]


################
### chacha20 ###
################
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


################
### poly1305 ###
################
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


###################
### bip324_ecdh ###
###################
def TaggedHash(tag, data):
    ss = hashlib.sha256(tag.encode('utf-8')).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()


def bip324_ecdh(priv, ellswift_theirs, ellswift_ours, initiating):
    ecdh_point_x32 = ellswift_ecdh_xonly(ellswift_theirs, priv)
    if initiating:
        # Initiating, place our public key encoding first.
        return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_ours + ellswift_theirs + ecdh_point_x32)
    else:
        # Responding, place their public key encoding first.
        return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_theirs + ellswift_ours + ecdh_point_x32)


#####################
### bip324_cipher ###
#####################
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
