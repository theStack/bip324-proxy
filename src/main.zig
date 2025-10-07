const std = @import("std");
const chacha = std.crypto.stream.chacha;
const hkdf = std.crypto.kdf.hkdf;
const net = std.net;
const onetimeauth = std.crypto.onetimeauth;
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

const BIP324_SHORTID_MSGTYPES = [_][]const u8 {
    "addr", "block", "blocktxn", "cmpctblock", "feefilter", "filteradd", "filterclear", "filterload",
    "getblocks", "getblocktxn", "getdata", "getheaders", "headers", "inv", "mempool", "merkleblock",
    "notfound", "ping", "pong", "sendcmpct", "tx", "getcfilters", "cfilter", "getcfheaders", "cfheaders",
    "getcfcheckpt", "cfcheckpt", "addrv2",
};

var stdout_buf: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
const stdout = &stdout_writer.interface;

const BitcoinMessage = struct {
    msg_type_buf: [12]u8,
    msg_type: []u8,
    payload_buf: [MAX_PROTOCOL_MESSAGE_LENGTH]u8,
    payload: []u8,

    fn init(msg_type: []const u8, payload: []u8) BitcoinMessage {
        var new: BitcoinMessage = undefined;
        @memcpy(new.msg_type_buf[0..msg_type.len], msg_type);
        @memset(new.msg_type_buf[msg_type.len..], 0);
        @memcpy(new.payload_buf[0..payload.len], payload);
        new.msg_type = new.msg_type_buf[0..msg_type.len];
        new.payload = new.payload_buf[0..payload.len];
        return new;
    }

    pub fn getMsgType(m: *const BitcoinMessage)    []u8 { return m.msg_type; }
    pub fn getMsgTypeRaw(m: *const BitcoinMessage) []u8 { return &m.msg_type_buf; }
    pub fn getPayload(m: *const BitcoinMessage)    []u8 { return m.payload; }
    pub fn getPayloadPtr(m: *BitcoinMessage) *[MAX_PROTOCOL_MESSAGE_LENGTH]u8  { return &m.payload_buf; }
    pub fn setPayloadLen(m: *BitcoinMessage, len: usize) void {
        std.debug.assert(len <= MAX_PROTOCOL_MESSAGE_LENGTH);
        m.payload = m.payload_buf[0..len];
    }
};

fn print(comptime fmt: []const u8, args: anytype) !void {
    try stdout.print(fmt, args);
    try stdout.flush();
}

fn doubleSha256Prefix(data: []u8) [4]u8 {
    var innerhash: [32]u8 = undefined;
    var resulthash: [32]u8 = undefined;
    Sha256.hash(data, &innerhash, .{});
    Sha256.hash(&innerhash, &resulthash, .{});
    return resulthash[0..4].*;
}

fn hkdfSha256(master_key: [32]u8, info: []const u8) [32]u8 {
    var resulthash: [32]u8 = undefined;
    hkdf.HkdfSha256.expand(&resulthash, info, master_key);
    return resulthash;
}

fn sendV1Message(conn: *const net.Server.Connection, msg: *const BitcoinMessage) !void {
    const msg_type_raw = msg.getMsgTypeRaw();
    std.debug.assert(msg_type_raw.len == 12);
    const payload = msg.getPayload();

    var header: [24]u8 = undefined;
    @memcpy(header[0..4], NET_MAGIC);
    @memcpy(header[4..16], msg_type_raw);
    std.mem.writeInt(u32, header[16..20], payload.len, .little);
    @memcpy(header[20..24], &doubleSha256Prefix(payload));
    try conn.writeAll(header);
    try conn.writeAll(payload);
}

fn recvV1MessagePayload(conn: *const net.Server.Connection, msg: *BitcoinMessage) !void {
    var header: [8]u8 = undefined;
    var n_read = try conn.stream.read(header[0..]); // TODO: use readAll?
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == header.len); // XXX

    const length: u32 = std.mem.readInt(u32, header[0..4], .little);
    if (length > MAX_PROTOCOL_MESSAGE_LENGTH) {
        try print("Received V1 message too large payload size (4 MB)\n", .{});
        return error.ConnectionClosed;
    }

    const payload_ptr = msg.getPayloadPtr();
    n_read = try conn.stream.read(payload_ptr[0..length]); // TODO: use readAll?
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == length); // XXX
    msg.setPayloadLen(length);

    const checksum = header[4..8];
    if (!std.mem.eql(u8, &doubleSha256Prefix(msg.getPayload()), checksum)) {
        try print("Received V1 message with incorrect checksum\n", .{});
        return error.ConnectionClosed;
    }
}

fn recvV1MessageFull(conn: *const net.Server.Connection) !*BitcoinMessage {
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
    var msg = std.heap.page_allocator.create(BitcoinMessage);
    errdefer std.heap.page_allocator.destroy(msg);
    msg.* = BitcoinMessage.init(msg_type, *.{});
    try recvV1MessagePayload(conn, &msg);
    return &msg;
}

fn bip324Send(conn: *const net.Server.Connection, send_l: *FSChaCha20, send_p: *FSChaCha20Poly1305, message: []u8, aad: []u8) !void {
    std.debug.assert(message.len <= MAX_PROTOCOL_MESSAGE_LENGTH); // TODO: check if this is the right limit
    var plain_len: [3]u8 = undefined;
    var enc_len: [3]u8 = undefined;
    std.mem.writeInt(u24, &plain_len, message.len, .little);
    send_l.crypt(&plain_len, &enc_len);
    const static_struct = struct {
        var plain_payload: [1 + MAX_PROTOCOL_MESSAGE_LENGTH]u8 = undefined;
        var enc_payload: [1 + MAX_PROTOCOL_MESSAGE_LENGTH + 16]u8 = undefined;
    };
    static_struct.plain_payload[0] = 0;
    @memcpy(static_struct.plain_payload[1..1+message.len], message);
    send_p.encrypt(static_struct.plain_payload, static_struct.plain_payload[0..0], aad, static_struct.enc_payload);
    try conn.writeAll(enc_len);
    try conn.writeAll(static_struct.enc_payload);
}

fn bip324Recv(conn: *const net.Server.Connection, recv_l: *FSChaCha20, recv_p: *FSChaCha20Poly1305, aad: []u8) ![]u8 {
    var enc_len: [3]u8 = undefined;
    var plain_len: [3]u8 = undefined;
    var n_read = try conn.stream.read(&enc_len); // TODO: use readAll?
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == plain_len.len); // XXX
    recv_l.crypt(&enc_len, &plain_len);
    const len = std.mem.readInt(u24, &plain_len, .little);
    if (len > MAX_PROTOCOL_MESSAGE_LENGTH) {
        try print("Received V2 message too large payload size (4 MB)\n", .{});
        return error.ConnectionClosed;
    }

    const static_struct = struct {
        var enc_payload: [1 + MAX_PROTOCOL_MESSAGE_LENGTH + 16]u8 = undefined;
        var plain_payload: [1 + MAX_PROTOCOL_MESSAGE_LENGTH]u8 = undefined;
    };
    n_read = try.conn.stream.read(static_struct.enc_payload[0..1+len+16]); // TODO: use readAll?
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == 1+len+16);

    // decrypt
    const ret = recv_p.decrypt(static_struct.enc_payload[0..1+len+16], aad, static_struct.plain_payload[0..1+len], static_struct.play_load[0..0]);
    if (!ret) {
        try print("Couldn't decrypt V2 message\n", .{});
        return error.ConnectionClosed;
    }
    if (static_struct.plain_payload[0] != 0) {
        try print("Received V2 message with invalid header version byte {x}\n", .{static_struct.plain_payload[0]});
    }
    var buffer = try std.heap.page_allocator.alloc(u8, len); // TODO: avoid dynamic memory allocations?
    @memcpy(&buffer, static_struct.plain_payload[1..1+len]);
    return buffer;
}

// TODO: collect conn, send_l, send_p, recv_l and recv_p in a struct
fn sendV2Message(conn: *const net.Server.Connection, send_l: *FSChaCha20, send_p: *FSChaCha20Poly1305, msg_type: []u8, payload: []u8) !void {
    std.debug.assert(msg_type.len <= 12);
    var header_buf: [13]u8 = [_]u8{0} ** 13;
    var header: []u8 = header_buf[0..0];
    for (0..BIP324_SHORTID_MSGTYPES.len) |i| {
        if (std.mem.eql(BIP324_SHORTID_MSGTYPES[i], msg_type)) {
            header_buf[0] = i+1;
            header = header_buf[0..1];
            break;
        }
    }
    if (header.len == 0) { // unknown type, use long encoding
        header_buf[0] = 0;
        @memcpy(header_buf[1..1+msg_type.len], msg_type);
        header = &header_buf;
    }

    var complete_message_buf: [MAX_PROTOCOL_MESSAGE_LENGTH]u8 = undefined; // TODO: enough?
    @memcpy(complete_message_buf[0..header.len], header);
    @memcpy(complete_message_buf[header.len..header.len+payload.len], payload);
    try bip324Send(conn, send_l, send_p, complete_message_buf[0..header.len+payload.len], complete_message_buf[0..0]);
}

fn recvV2Message(conn: *const net.Server.Connection, recv_l: *FSChaCha20, recv_p: *FSChaCha20Poly1305) !struct {[]u8, []u8} {
    var dummy_buf: [1]u8 = undefined;
    const complete_msg = try bip324Recv(conn, recv_l, recv_p, dummy_buf[0..0]);
    if (1 <= complete_msg[0] and complete_msg[0] <= BIP324_SHORTID_MSGTYPES.len) {
        return .{ BIP324_SHORTID_MSGTYPES[complete_msg[0]-1], complete_msg[1..] };
    } else if (complete_msg[0] == 0) {
        var msg_type = complete_msg[0..12];
        while (msg_type.len > 0 and msg_type[msg_type.len-1] == 0) {
            msg_type = msg_type[0..msg_type.len-1];
        }
        // TODO: meeeeh, where to allocate the memory for the message type?
        return .{ msg_type, complete_msg[12..] };
    } else {
        try print("Received V2 message with invalid type {d}\n", .{ complete_msg[0] });
        return error.ConnectionError;
    }
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

    var first_msg = BitcoinMessage.init("version", &.{});
    try recvV1MessagePayload(proxy_server, &first_msg);
    const msg_payload = first_msg.getPayload();
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
    try print("our pubkey sent!\n", .{});
    try proxy_client.writeAll(garbage);
    try print("our garbage sent!\n", .{});
    // - receive their pubkey
    var pubkey_theirs: [64]u8 = undefined;
    const n_read = try proxy_client.read(pubkey_theirs[0..]);
    if (n_read == 0) return error.ConnectionClosed;
    std.debug.assert(n_read == 64);
    try print("their pubkey received!\n", .{});
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
    try print("garbage terminator sent!\n", .{});

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

    fn computeTag(a: *AEADChaCha20Poly1305, aad: []const u8, cipher: []u8, tag: []u8) void {
        const PADDING: [16]u8 = [_]u8{0} ** 16;
        var first_block: [64]u8 = undefined;
        a.chacha20.stream(&first_block);

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
        poly1305.update(&length_desc);

        // output tag
        var tag_: [16]u8 = undefined;
        poly1305.final(&tag_);
        @memcpy(tag[0..16], tag_[0..16]);
    }

    pub fn encrypt(a: *AEADChaCha20Poly1305, plain1: []const u8, plain2: []const u8, aad: []const u8, nonce: [12]u8, cipher: []u8) void {
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
        if (!std.mem.eql(u8, &expected_tag, cipher[cipher.len - 16..])) { return false; }

        // decrypt, start at block 1
        a.chacha20.crypt(cipher[0..plain1.len], plain1);
        a.chacha20.crypt(cipher[plain1.len..plain1.len+plain2.len], plain2);
        return true;
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
        //if (fscp.packet_counter == fscp.rekey_interval) {
        if (fscp.packet_counter % fscp.rekey_interval == 0) {
            var one_block: [64]u8 = undefined;
            var new_nonce: [12]u8 = .{0xff,0xff,0xff,0xff,0,0,0,0,0,0,0,0};
            @memcpy(new_nonce[4..12], nonce[4..12]);
            fscp.aead.stream(new_nonce, &one_block);
            // switch keys
            const nonceval = std.mem.readInt(u64, new_nonce[4..12], .little);
            std.debug.print("8byte nonce val: {x}, new key: {x}\n", .{nonceval, one_block[0..32]});
            fscp.aead.setKey(one_block[0..32].*);
            //fscp.packet_counter = 0;
        }
    }

    pub fn encrypt(fscp: *FSChaCha20Poly1305, plain1: []const u8, plain2: []const u8, aad: []u8, cipher: []u8) void {
        var nonce: [12]u8 = .{0,0,0,0,0,0,0,0,0,0,0,0};
        std.mem.writeInt(u32, nonce[0..4], fscp.packet_counter % fscp.rekey_interval, .little);
        std.mem.writeInt(u64, nonce[4..12], fscp.packet_counter / fscp.rekey_interval, .little);
        fscp.aead.encrypt(plain1, plain2, aad, nonce, cipher);
        fscp.nextPacket(nonce);
    }

    pub fn decrypt(fscp: *FSChaCha20Poly1305, cipher: []u8, aad: []u8, plain1: []u8, plain2: []u8) bool {
        var nonce: [12]u8 = .{0,0,0,0,0,0,0,0,0,0,0,0};
        std.mem.writeInt(u32, nonce[0..4], fscp.packet_counter % fscp.rekey_interval, .little);
        std.mem.writeInt(u64, nonce[4..12], fscp.packet_counter / fscp.rekey_interval, .little);
        const ret = fscp.aead.decrypt(cipher, aad, nonce, plain1, plain2);
        fscp.nextPacket(nonce);
        return ret;
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

    // TestFSChaCha20Poly1305("8349b7a2690b63d01204800c288ff1138a1d473c832c90ea8b3fc102d0bb3adc"
    //                        "44261b247c7c3d6760bfbe979d061c305f46d94c0582ac3099f0bf249f8cb234",
    //                        "",
    //                        "3bd2093fcbcb0d034d8c569583c5425c1a53171ea299f8cc3bbf9ae3530adfce",
    //                        60000,
    //                        "30a6757ff8439b975363f166a0fa0e36722ab35936abd704297948f45083f4d4"
    //                        "99433137ce931f7fca28a0acd3bc30f57b550acbc21cbd45bbef0739d9caf30c"
    //                        "14b94829deb27f0b1923a2af704ae5d6");
    const plain: [64]u8 = ("\x83\x49\xb7\xa2\x69\x0b\x63\xd0\x12\x04\x80\x0c\x28\x8f\xf1\x13" ++
                           "\x8a\x1d\x47\x3c\x83\x2c\x90\xea\x8b\x3f\xc1\x02\xd0\xbb\x3a\xdc" ++
                           "\x44\x26\x1b\x24\x7c\x7c\x3d\x67\x60\xbf\xbe\x97\x9d\x06\x1c\x30" ++
                           "\x5f\x46\xd9\x4c\x05\x82\xac\x30\x99\xf0\xbf\x24\x9f\x8c\xb2\x34").*;
    const aad: []u8 = &[_]u8{};
    const newkey: [32]u8 = ("\x3b\xd2\x09\x3f\xcb\xcb\x0d\x03\x4d\x8c\x56\x95\x83\xc5\x42\x5c" ++
                            "\x1a\x53\x17\x1e\xa2\x99\xf8\xcc\x3b\xbf\x9a\xe3\x53\x0a\xdf\xce").*;
    const msg_idx: u64 = 60000;
    var cipher: [80]u8 = undefined;

    var dummy_tag: [16]u8 = undefined;
    var fscp = FSChaCha20Poly1305.init(newkey, 224);
    // dummy encryptions first
    for (0..msg_idx) |_| {
        fscp.encrypt(dummy_tag[0..0], dummy_tag[0..0], dummy_tag[0..0], &dummy_tag);
    }
    try print("dummy tag after all iterations: {x}\n", .{dummy_tag});
    // single encrypt
    fscp.encrypt(&plain, plain[0..0], aad, &cipher);
    //fscp.encrypt(plain[0..0], &plain, aad, &cipher);
    try print("TEST FSChaCha20Poly1305 result after single encryption: {x}\n", .{cipher});

    // dummy decryptions
    var fscp_dec = FSChaCha20Poly1305.init(newkey, 224);
    for (0..msg_idx) |_| {
        //try print("iteration {d}\n", .{i});
        _ = fscp_dec.decrypt(&dummy_tag, dummy_tag[0..0], dummy_tag[0..0], dummy_tag[0..0]);
        //try print("done\n", .{});
        //std.debug.assert(ret);
    }
    var decipher: [64]u8 = undefined;
    const ret = fscp_dec.decrypt(&cipher, aad, &decipher, decipher[0..0]);
    try print("ret ===== {}\n", .{ret});
    const retret = std.mem.eql(u8, &decipher, &plain);
    try print("retret ===== {}\n", .{retret});

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
