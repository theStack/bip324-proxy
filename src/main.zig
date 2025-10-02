const std = @import("std");
const chacha = std.crypto.stream.chacha;
const hkdf = std.crypto.kdf.hkdf;
const hmac = std.crypto.auth.hmac; // TODO: needed?
const net = std.net;
const onetimeauth = std.onetimeauth;
const random = std.crypto.random;
const Sha256 = std.crypto.hash.sha2.Sha256;
const s = @cImport({
    @cInclude("secp256k1_ellswift.h");
});

const BIP324_PROXY_PORT: u16 = 1324;
const NET_MAGIC: [4]u8 = .{0xf9,0xbe,0xb4,0xd9}; // mainnet
//const NET_MAGIC: [4]u8 = .{0x0a,0x03,0xcf,0x40}; // signet
const V1_PREFIX: [16]u8 = NET_MAGIC ++ .{'v','e','r','s','i','o','n',0,0,0,0,0};
const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4 * 1000 * 1000;

var stdout_buf: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
const stdout = &stdout_writer.interface;

fn print(comptime fmt: []const u8, args: anytype) !void {
    try stdout.print(fmt, args);
    try stdout.flush();
}

fn doubleSha256(data: []u8) [32]u8 {
    var innerhash: [32]u8 = undefined;
    var resulthash: [32]u8 = undefined;
    Sha256.hash(data, &innerhash, .{});
    Sha256.hash(&innerhash, &resulthash, .{});
    return resulthash;
}

fn hkdfSha256(master_key: [32]u8, info: []const u8) [32]u8 {
    var resulthash: [32]u8 = undefined;
    hkdf.HkdfSha256.expand(&resulthash, info, master_key);
    return resulthash;
}

fn recvV1MessagePayload(conn: *const net.Server.Connection) ![]u8 {
    var header: [8]u8 = undefined;
    var n_read = try conn.stream.read(header[0..]); // TODO: use readAll?
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == header.len); // XXX

    const length: u32 = std.mem.readInt(u32, header[0..4], .little);
    if (length > MAX_PROTOCOL_MESSAGE_LENGTH) {
        try print("Received V1 message too large payload size (4 MB)\n", .{});
        return error.ConnectionClosed;
    }

    var buffer = try std.heap.page_allocator.alloc(u8, length);
    n_read = try conn.stream.read(buffer[0..length]); // TODO: use readAll?
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == buffer.len); // XXX

    const checksum = header[4..8];
    if (!std.mem.eql(u8, doubleSha256(buffer)[0..4], checksum)) {
        try print("Received V1 message with incorrect checksum\n", .{});
        return error.ConnectionClosed;
    }

    return buffer;
}

fn recvV1MessageFull(conn: *const net.Server.Connection) !struct {[]u8, []u8} {
    var net_magic: [4]u8 = undefined;
    var n_read = try conn.stream.read(net_magic[0..]); // TODO: use readAll?
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == net_magic.len); // XXX
    if (!std.mem.eql(u8, net_magic, NET_MAGIC)) {
        try print("Received V1 message with wrong NET_MAGIC\n", .{});
        return error.ConnectionClosed;
    }

    var msg_type_buf: [12]u8 = undefined;
    n_read = try conn.stream.readAll(msg_type_buf[0..]);
    if (n_read == 0) return error.ConnectionClosed;
    var msg_type = msg_type_buf[0..];
    while (msg_type.len > 0 and msg_type[msg_type.len-1] == 0) {
        msg_type = msg_type[0..msg_type.len-1];
    }
    print("msgtype: ", .{});
    for (msg_type) |b| {
        print("{x} ", .{b});
    }
    print("\n", .{});
    const msg_payload = recvV1MessagePayload(conn);
    return .{ msg_type, msg_payload };
}

fn bip324ProxyHandler(proxy_server: *const net.Server.Connection) !void {
    // peek into receiver buffer byte for byte to detect early if the first
    // incoming message is not a bitcoin p2p v1 message; in that case we can't
    // do anything (we wouldn't know the remote destination to send data to) and
    // have to close the local connection
    var received_prefix: [16]u8 = undefined;

    try print("Received prefix bytes: ", .{});
    for (0..V1_PREFIX.len) |i| {
        var byte_buf: [1]u8 = undefined;
        const n_read = try proxy_server.stream.read(&byte_buf);
        if (n_read == 0) return error.ConnectionClosed;
        const byte = byte_buf[0];
        try print("{x} ", .{byte});
        if (byte != V1_PREFIX[i]) {
            try print("V1 prefix mismatch after {d} bytes, close connection.\n", .{i+1});
            // TODO: show expected/received byte-strings
            return error.ConnectionClosed; // TODO: right error code?
        }
        received_prefix[i] = byte;
    }
    try print("\n", .{});

    const msg_payload = try recvV1MessagePayload(proxy_server);
    defer std.heap.page_allocator.free(msg_payload);
    try print("Version payload length: {d} bytes\n", .{msg_payload.len});

    // decode VERSION message
    // TODO: check that VERSION message has minimum needed size
    const addr_recv = msg_payload[20..46];
    const remote_addr_ipv6 = addr_recv[8..24];
    const IPV6_PREFIX: [12]u8 = .{0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (!std.mem.eql(u8, remote_addr_ipv6[0..12], &IPV6_PREFIX)) {
        try print("IPv6 is not supported yet.\n", .{});
        return error.ConnectionClosed;
    }
    const remote_ip_bytes = remote_addr_ipv6[12..16];
    const remote_port = std.mem.readInt(u16, addr_recv[24..26], .big);
    const remote_addr = net.Address.initIp4(remote_ip_bytes.*, remote_port);
    // TODO: decode and print also user agent
    try print("    => Remote address: {f}\n", .{remote_addr});

    // connect to target node
    var proxy_client = try net.tcpConnectToAddress(remote_addr);
    defer proxy_client.close();
    try print("[>] Connected to {f}, initiating BIP324 handshake.\n", .{ remote_addr });

    // BIP324 key exchange phase
    // - create ellswift keypair
    var seckey: [32]u8 = undefined;
    var pubkey_ours: [64]u8 = undefined;
    random.bytes(&seckey);
    const ctx = s.secp256k1_context_create(s.SECP256K1_CONTEXT_NONE);
    defer s.secp256k1_context_destroy(ctx);
    var ret = s.secp256k1_ellswift_create(ctx, &pubkey_ours, &seckey, null);
    std.debug.assert(ret == 1);
    // - generate random-length garbage
    var garbage_buf: [4096]u8 = undefined;
    random.bytes(&garbage_buf);
    const garbage_len = random.intRangeAtMost(u16, 0, 4096);
    const garbage = garbage_buf[0..garbage_len];
    // - send our pubkey + garbage
    try proxy_client.writeAll(&pubkey_ours);
    try proxy_client.writeAll(garbage);
    // - receive their pubkey
    var pubkey_theirs: [64]u8 = undefined;
    const n_read = try proxy_client.read(pubkey_theirs[0..]);
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == 64);
    try print("pubkey received!!!!!\n", .{});
    // TODO: implement v1 fallback? probably not
    // - perform ECDH
    var shared_secret: [32]u8 = undefined;
    ret = s.secp256k1_ellswift_xdh(ctx, &shared_secret, &pubkey_ours, &pubkey_theirs,
        &seckey, 0, s.secp256k1_ellswift_xdh_hash_function_bip324, null);
    std.debug.assert(ret == 1);
    // - derive key material
    const salt = "bitcoin_v2_shared_secret" ++ NET_MAGIC;
    const master_key = hkdf.HkdfSha256.extract(salt[0..], &shared_secret);
    const initiator_L = hkdfSha256(master_key, "initiator_L");
    const initiator_P = hkdfSha256(master_key, "initiator_P");
    const responder_L = hkdfSha256(master_key, "responder_L");
    const responder_P = hkdfSha256(master_key, "responder_P");
    const garbage_terminators = hkdfSha256(master_key, "garbage_terminators");
    const session_id = hkdfSha256(master_key, "session_id");
    const send_garbage_terminator = garbage_terminators[0..16];
    const recv_garbage_terminator = garbage_terminators[16..32];
    // - send garbage terminator, detect partner garbage
    try proxy_client.writeAll(send_garbage_terminator);

    _ = initiator_L;
    _ = initiator_P;
    _ = responder_L;
    _ = responder_P;
    _ = recv_garbage_terminator;
    _ = session_id;
}

const ChaCha20 = struct {
    key: [32]u8,
    buffer: [64]u8,
    bufleft: usize = 0,
    nonce: [12]u8,
    block_counter: u32 = 0,

    pub fn init(key: [32]u8) ChaCha20 {
        return ChaCha20 {
            .key = key,
            .buffer = [_]u8{0} ** 64,
            .nonce = [_]u8{0} ** 12,
        };
    }

    pub fn setKey(c: *ChaCha20, key: [32]u8) void {
        c.key = key;
        c.bufleft = 0;
    }

    pub fn seek(c: *ChaCha20, nonce: [12]u8, block_counter: u32) void {
        c.nonce = nonce;
        c.block_counter = block_counter;
        c.bufleft = 0;
    }

    pub fn crypt(c: *ChaCha20, in_: []const u8, out_: []u8) void {
        var in = in_;
        var out = out_;
        std.debug.assert(in.len == out.len);

        if (in.len == 0) return;
        if (c.bufleft > 0) {
            const reuse = @min(c.bufleft, in.len);
            for (0..reuse) |i| {
                out[i] = in[i] ^ c.buffer[64 - c.bufleft + i];
            }
            c.bufleft -= reuse;
            out = out[reuse..];
            in = in[reuse..];
        }
        if (in.len >= 64) {
            const blocks: u64 = in.len / 64;
            chacha.ChaCha20IETF.xor(out[0 .. blocks * 64], in[0 .. blocks * 64], c.block_counter, c.key, c.nonce);
            c.block_counter += @intCast(blocks);
            out = out[64 * blocks ..];
            in = in[64 * blocks ..];
        }
        if (in.len > 0) {
            chacha.ChaCha20IETF.stream(&c.buffer, c.block_counter, c.key, c.nonce);
            c.block_counter += 1;
            for (0..in.len) |i| {
                out[i] = in[i] ^ c.buffer[i];
            }
            c.bufleft = 64 - in.len;
        }
    }

    pub fn stream(c: *ChaCha20, out_: []u8) void {
        var out = out_;
        if (out.len == 0) return;
        if (c.bufleft > 0) {
            const reuse = @min(c.bufleft, out.len);
            @memcpy(out[0..reuse], c.buffer[c.buffer.len - c.bufleft .. c.buffer.len - c.bufleft + reuse]);
            c.bufleft -= reuse;
            out = out[reuse..];
        }
        if (out.len >= 64) {
            const blocks = out.len / 64;
            chacha.ChaCha20IETF.stream(out[0 .. blocks * 64], c.block_counter, c.key, c.nonce);
            c.block_counter += @intCast(blocks);
            out = out[64 * blocks ..];
        }
        if (out.len > 0) {
            chacha.ChaCha20IETF.stream(&c.buffer, c.block_counter, c.key, c.nonce);
            c.block_counter += 1;
            @memcpy(out, c.buffer[0 .. out.len]);
            c.bufleft = 64 - out.len;
        }
    }
};

const FSChaCha20 = struct {
    chacha20: ChaCha20,
    rekey_interval: u64,
    chunk_counter: u64 = 0,
    // TODO: introduce rekey_counter to avoid division

    pub fn init(key: [32]u8, rekey_interval: u32) FSChaCha20 {
        return FSChaCha20 {
            .chacha20 = ChaCha20.init(key),
            .rekey_interval = rekey_interval,
        };
    }

    pub fn crypt(fsc: *FSChaCha20, in: []const u8, out: []u8) void {
        std.debug.assert(in.len == out.len);

        fsc.chacha20.crypt(in, out);
        fsc.chunk_counter += 1;
        if (fsc.chunk_counter == fsc.rekey_interval) {
            var new_key: [32]u8 = undefined;
            fsc.chacha20.stream(&new_key);
            fsc.chacha20.setKey(new_key);
            var nonce: [12]u8 = .{0,0,0,0,0,0,0,0,0,0,0,0};
            std.mem.writeInt(u64, nonce[4..12], fsc.chunk_counter / fsc.rekey_interval, .little);
            fsc.chacha20.seek(nonce, 0);
            fsc.chunk_counter = 0;
        }
    }
};

const AEADChaCha20Poly1305 = struct {
    chacha20: ChaCha20,

    pub fn init(key: [32]u8) AEADChaCha20Poly1305 {
        return AEADChaCha20Poly1305 {
            .chacha20 = ChaCha20.init(key),
        };
    }

    pub fn setKey(a: *AEADChaCha20Poly1305, key: [32]u8) void {
        a.chacha20.setKey(key);
    }

    fn computeTag(a: *AEADChaCha20Poly1305, aad: []u8, cipher: []u8, tag: []u8) void {
        const PADDING: [16]u8 = [_]u8{0} ** 16;
        var first_block: [64]u8 = undefined;
        a.chacha20.stream(first_block);

        // use first 32 bytes as poly1305 key
        var poly1305 = onetimeauth.Poly1305.init(first_block[0..32]);

        // compute tag
        // - process padded AAD
        const aad_padding_length = (16 - aad.len % 16) % 16;
        poly1305.update(aad);
        poly1305.update(PADDING[0..aad_padding_length]);
        // - process padded ciphertext
        const cipher_padding_length = (16 - cipher.len % 16) % 16;
        poly1305.update(cipher);
        poly1305.update(PADDING[0..cipher_padding_length]);
        // - process AAD and plaintext length
        var length_desc: [16]u8 = undefined;
        std.mem.writeInt(u64, length_desc[0..8], aad.len, .little);
        std.mem.writeInt(u64, length_desc[8..16], cipher.len, .little);
        poly1305.update(length_desc);

        // output tag
        poly1305.final(tag);
    }

    pub fn encrypt(a: *AEADChaCha20Poly1305, plain1: []u8, plain2: []u8, aad: []u8, nonce: [12]u8, cipher: []u8) void {
        std.debug.assert(cipher.len == plain1.len + plain2.len + 16);

        // encrypt, start at block 1
        a.chacha20.seek(nonce, 1);
        a.chacha20.crypt(plain1, cipher[0..plain1.len]);
        a.chacha20.crypt(plain2, cipher[plain1.len..plain1.len+plain2.len]);

        // seek to block 0, compute tag using key from there
        a.chacha20.seek(nonce, 0);
        a.computeTag(aad, cipher[0 .. cipher.len - 16], cipher[cipher.len - 16..]);
    }

    pub fn decrypt(a: *AEADChaCha20Poly1305, cipher: []u8, aad: []u8, nonce: [12]u8, plain1: []u8, plain2: []u8) bool {
        std.debug.assert(cipher.len == plain1.len + plain2.len + 16);

        // verify tag, using key from block 0
        a.chacha20.seek(nonce, 0);
        var expected_tag: [16]u8 = undefined;
        a.computeTag(aad, cipher[0 .. cipher.len - 16], &expected_tag);
        if (!std.mem.eql(u8, expected_tag, cipher[cipher.len - 16..])) { return false; }

        // decrypt, start at block 1
        a.chacha20.crypt(cipher[0..plain1.len], plain1);
        a.chacha20.crypt(cipher[plain1.len..plain1.len+plain2.len], plain2);
    }

    pub fn stream(a: *AEADChaCha20Poly1305, nonce: [12]u8, out: []u8) void {
        a.chacha20.seek(nonce, 1);
        a.chacha20.stream(out);
    }
};

const FSChaCha20Poly1305 = struct {
    aead: AEADChaCha20Poly1305,
    rekey_interval: u32,
    packet_counter: u32 = 0,
    // TODO: introduce rekey_counter to avoid division

    pub fn init(key: [32]u8, rekey_interval: u32) FSChaCha20Poly1305 {
        return FSChaCha20Poly1305 {
            .aead = AEADChaCha20Poly1305.init(key),
            .rekey_interval = rekey_interval,
        };
    }

    fn nextPacket(fscp: *FSChaCha20Poly1305, nonce: [12]u8) void {
        fscp.packet_counter += 1;
        if (fscp.packet_counter == fscp.rekey_interval) {
            var one_block: [64]u8 = undefined;
            var new_nonce: [12]u8 = .{0xff,0xff,0xff,0xff,0,0,0,0,0,0,0,0};
            @memcpy(new_nonce[4..12], nonce[4..12]);
            fscp.aead.stream(&new_nonce, &one_block);
            // switch keys
            fscp.aead.setKey(one_block[0..32]);
            fscp.packet_counter = 0;
        }
    }

    pub fn encrypt(fscp: *FSChaCha20Poly1305, plain1: []u8, plain2: []u8, aad: []u8, cipher: []u8) void {
        var nonce: [12]u8 = .{0,0,0,0,0,0,0,0,0,0,0,0};
        std.mem.writeInt(u32, nonce[0..4], fscp.packet_counter % fscp.rekey_interval, .little);
        std.mem.writeInt(u64, nonce[4..12], fscp.packet_counter / fscp.rekey_interval, .little);
        // TODO: encrypt AEAD
        _ = plain1; _ = plain2; _ = aad; _ = cipher;
        fscp.nextPacket(nonce);
    }

    pub fn decrypt(fscp: *FSChaCha20Poly1305, cipher: []u8, aad: []u8, plain1: []u8, plain2: []u8) void {
        var nonce: [12]u8 = .{0,0,0,0,0,0,0,0,0,0,0,0};
        std.mem.writeInt(u32, nonce[0..4], fscp.packet_counter % fscp.rekey_interval, .little);
        std.mem.writeInt(u64, nonce[4..12], fscp.packet_counter / fscp.rekey_interval, .little);
        // TODO: decrypt AEAD
        _ = plain1; _ = plain2; _ = aad; _ = cipher;
        fscp.nextPacket(nonce);
    }
};

pub fn main() !void {
    try print("---------------------\n", .{});
    try print(" BIP324 proxy server \n", .{});
    try print("---------------------\n", .{});

    // // Forward secure ChaCha20
    // TestFSChaCha20("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    //                "0000000000000000000000000000000000000000000000000000000000000000",
    //                256,
    //                "a93df4ef03011f3db95f60d996e1785df5de38fc39bfcb663a47bb5561928349");

    const key2: [32]u8 = ("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").*;
    const msg: [32]u8 = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" ++
                         "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f").*;
    var output: [32]u8 = undefined;
    const rekey_interval: u32 = 256;
    var fs = FSChaCha20.init(key2, rekey_interval);
    for (0..rekey_interval) |_| {
        fs.crypt(&msg, &output);
    }
    fs.crypt(&msg, &output);
    try print("TEST FSChaCha20 result after key rotation: {x}\n", .{output});

    const server_addr = try net.Address.parseIp4("127.0.0.1", BIP324_PROXY_PORT);
    var server = try server_addr.listen(.{.reuse_address = true});
    defer server.deinit();
    try print("Waiting for incoming v1 connections on {f}...\n", .{server.listen_address});

    while (true) {
        const proxy_server = try server.accept();
        defer proxy_server.stream.close();
        try print("[<] New connection from {f}\n", .{proxy_server.address});
        // TODO: start this up in a new thread
        bip324ProxyHandler(&proxy_server) catch {
            try print("Connection was closed.\n", .{});
        };
    }
}
