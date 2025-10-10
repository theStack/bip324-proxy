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
const c = @cImport({
    @cInclude("poll.h");
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
    pub fn getMsgTypeRaw(m: *const BitcoinMessage) []const u8 { return &m.msg_type_buf; }
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

fn recvAll(conn: *const net.Stream, output: []u8) !void {
    var out = output;
    var total_read: usize = 0;
    while (out.len > 0) {
        const bytes_to_read = @min(out.len, 16384);
        const n_read = try conn.read(out[0..bytes_to_read]);
        if (n_read == 0) return error.ConnectionClosed;
        out = out[n_read..];
        total_read += n_read;
    }
    std.debug.assert(total_read == output.len);
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

fn sendV1Message(conn: *const net.Stream, msg: *const BitcoinMessage) !void {
    const msg_type_raw = msg.getMsgTypeRaw();
    std.debug.assert(msg_type_raw.len == 12);
    const payload = msg.getPayload();

    var header: [24]u8 = undefined;
    @memcpy(header[0..4], &NET_MAGIC);
    @memcpy(header[4..16], msg_type_raw);
    std.mem.writeInt(u32, header[16..20], @intCast(payload.len), .little);
    @memcpy(header[20..24], &doubleSha256Prefix(payload));
    try conn.writeAll(&header);
    try conn.writeAll(payload);
}

fn recvV1MessagePayload(conn: *const net.Stream, msg: *BitcoinMessage) !void {
    var header: [8]u8 = undefined;
    try recvAll(conn, header[0..]);

    const length: u32 = std.mem.readInt(u32, header[0..4], .little);
    if (length > MAX_PROTOCOL_MESSAGE_LENGTH) {
        try print("Received V1 message too large payload size (4 MB)\n", .{});
        return error.ConnectionClosed;
    }

    if (length > 0) {
        const payload_ptr = msg.getPayloadPtr();
        try recvAll(conn, payload_ptr[0..length]);
    }
    msg.setPayloadLen(length);

    const checksum = header[4..8];
    if (!std.mem.eql(u8, &doubleSha256Prefix(msg.getPayload()), checksum)) {
        try print("Received V1 message with incorrect checksum\n", .{});
        return error.ConnectionClosed;
    }
}

fn recvV1MessageFull(conn: *const net.Stream) !*BitcoinMessage {
    var net_magic: [4]u8 = undefined;
    try recvAll(conn, net_magic[0..]);
    if (!std.mem.eql(u8, &net_magic, &NET_MAGIC)) {
        try print("Received V1 message with wrong NET_MAGIC\n", .{});
        return error.ConnectionClosed;
    }

    var msg_type_buf: [12]u8 = undefined;
    try recvAll(conn, msg_type_buf[0..]);
    var msg_type: []u8 = msg_type_buf[0..];
    while (msg_type.len > 0 and msg_type[msg_type.len-1] == 0) {
        msg_type = msg_type[0..msg_type.len-1];
    }
    const msg = try std.heap.page_allocator.create(BitcoinMessage);
    errdefer std.heap.page_allocator.destroy(msg);
    msg.* = BitcoinMessage.init(msg_type, &.{});
    try recvV1MessagePayload(conn, msg);
    return msg;
}

const BIP324Ciphers = struct {
    send_l: FSChaCha20,
    send_p: FSChaCha20Poly1305,
    recv_l: FSChaCha20,
    recv_p: FSChaCha20Poly1305,

    fn init(send_l_key: *const [32]u8, send_p_key: *const [32]u8,
            recv_l_key: *const [32]u8, recv_p_key: *const [32]u8) BIP324Ciphers {
        const REKEY_INTERVAL: u32 = 224;
        return BIP324Ciphers {
            .send_l = FSChaCha20.init(send_l_key.*, REKEY_INTERVAL),
            .send_p = FSChaCha20Poly1305.init(send_p_key.*, REKEY_INTERVAL),
            .recv_l = FSChaCha20.init(recv_l_key.*, REKEY_INTERVAL),
            .recv_p = FSChaCha20Poly1305.init(recv_p_key.*, REKEY_INTERVAL),
        };
    }
};

fn bip324Send(conn: *const net.Stream, bip324_ciphers: *BIP324Ciphers, msg: []u8, aad: []u8) !void {
    var plain_len: [3]u8 = undefined;
    std.mem.writeInt(u24, &plain_len, @intCast(msg.len), .little);
    var raw_bytes = try std.heap.page_allocator.alloc(u8, plain_len.len + 1 + msg.len + 16);
    defer std.heap.page_allocator.free(raw_bytes);
    bip324_ciphers.send_l.crypt(&plain_len, raw_bytes[0..3]);
    raw_bytes[3] = 0;
    @memcpy(raw_bytes[4..4+msg.len], msg);
    bip324_ciphers.send_p.encrypt(raw_bytes[3..4+msg.len], &.{}, aad, raw_bytes[3..]);
    try conn.writeAll(raw_bytes);
}

fn bip324Recv(conn: *const net.Stream, bip324_ciphers: *BIP324Ciphers, aad: []const u8) ![]u8 {
    var enc_len: [3]u8 = undefined;
    var plain_len: [3]u8 = undefined;
    try recvAll(conn, &enc_len);
    bip324_ciphers.recv_l.crypt(&enc_len, &plain_len);
    const len = std.mem.readInt(u24, &plain_len, .little);
    const MAX_CONTENTS_LEN = 1 + 12 + MAX_PROTOCOL_MESSAGE_LENGTH;
    if (len > MAX_CONTENTS_LEN) {
        try print("Received V2 message too large payload size (4 MB)\n", .{});
        return error.ConnectionClosed;
    }

    var decrypt_buffer = try std.heap.page_allocator.alloc(u8, 1 + len + 16);
    defer std.heap.page_allocator.free(decrypt_buffer[0..]);
    try recvAll(conn, decrypt_buffer);

    // decrypt
    var plain = try std.heap.page_allocator.alloc(u8, 1+len);
    errdefer std.heap.page_allocator.free(plain);
    const ret = bip324_ciphers.recv_p.decrypt(decrypt_buffer, aad, plain[0..], &.{});
    if (!ret) {
        try print("Couldn't decrypt V2 message\n", .{});
        return error.ConnectionClosed;
    }
    if (plain[0] != 0) {
        try print("Received V2 message with invalid header version byte {x}\n", .{plain[0]});
    }
    return plain;
}

fn sendV2Message(conn: *const net.Stream, bip324_ciphers: *BIP324Ciphers, msg: *const BitcoinMessage) !void {
    const msg_type = msg.getMsgType();
    const payload = msg.getPayload();

    var header_buf: [13]u8 = [_]u8{0} ** 13;
    var header: []u8 = &.{};
    for (0..BIP324_SHORTID_MSGTYPES.len) |i| {
        if (std.mem.eql(u8, BIP324_SHORTID_MSGTYPES[i], msg_type)) {
            header_buf[0] = @intCast(i+1);
            header = header_buf[0..1];
            break;
        }
    }
    if (header.len == 0) { // unknown type, use long encoding
        header_buf[0] = 0;
        @memcpy(header_buf[1..1+msg_type.len], msg_type);
        header = &header_buf;
    }

    var complete_msg = try std.heap.page_allocator.alloc(u8, header.len + payload.len);
    defer std.heap.page_allocator.free(complete_msg);
    @memcpy(complete_msg[0..header.len], header);
    @memcpy(complete_msg[header.len..header.len+payload.len], payload);
    try bip324Send(conn, bip324_ciphers, complete_msg, &.{});
}

fn recvV2Message(conn: *const net.Stream, bip324_ciphers: *BIP324Ciphers) !*BitcoinMessage {
    const complete_msg_with_header_byte = try bip324Recv(conn, bip324_ciphers, &.{});
    defer std.heap.page_allocator.free(complete_msg_with_header_byte);
    const complete_msg = complete_msg_with_header_byte[1..];
    var msg_type: []const u8 = &.{};
    var payload: []u8 = &.{};
    if (1 <= complete_msg[0] and complete_msg[0] <= BIP324_SHORTID_MSGTYPES.len) {
        msg_type = BIP324_SHORTID_MSGTYPES[complete_msg[0]-1];
        payload = complete_msg[1..];
    } else if (complete_msg[0] == 0) {
        msg_type = complete_msg[1..13];
        while (msg_type.len > 0 and msg_type[msg_type.len-1] == 0) {
            msg_type = msg_type[0..msg_type.len-1];
        }
        payload = complete_msg[13..];
    } else {
        try print("Received V2 message with invalid type {d}\n", .{ complete_msg[0] });
        return error.ConnectionError;
    }
    const msg = try std.heap.page_allocator.create(BitcoinMessage);
    msg.* = BitcoinMessage.init(msg_type, payload);
    return msg;
}

fn bip324ProxyHandler(proxy_server: *const net.Stream) !void {
    // peek into receiver buffer byte for byte to detect early if the first
    // incoming message is not a bitcoin p2p v1 message; in that case we can't
    // do anything (we wouldn't know the remote destination to send data to) and
    // have to close the local connection
    var received_prefix: [16]u8 = undefined;

    try print("Received prefix bytes: ", .{});
    for (0..V1_PREFIX.len) |i| {
        var byte_buf: [1]u8 = undefined;
        try recvAll(proxy_server, &byte_buf);
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
    try recvAll(&proxy_client, pubkey_theirs[0..]);
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
    var bip324_ciphers = BIP324Ciphers.init(&initiator_L, &initiator_P, &responder_L, &responder_P);
    // - send garbage terminator
    try proxy_client.writeAll(send_garbage_terminator);
    try print("garbage terminator sent!\n", .{});
    try bip324Send(&proxy_client, &bip324_ciphers, &.{}, garbage);
    try print("garbage aad sent!\n", .{});
    // - detect partner garbage
    var garbage_and_term_buf: [4095+16]u8 = undefined;
    try recvAll(&proxy_client, garbage_and_term_buf[0..16]);
    var garbage_term_found = false;
    var partner_garbage: []u8 = undefined;
    for (0..4096) |i| {
        if (std.mem.eql(u8, garbage_and_term_buf[i..i+16], recv_garbage_terminator)) {
            partner_garbage = garbage_and_term_buf[0..i];
            garbage_term_found = true;
            break;
        }
        try recvAll(&proxy_client, garbage_and_term_buf[i+16..i+16+1]);
    }
    if (garbage_term_found) {
        try print("YAY, garbage terminator found!\n", .{});
    } else {
        try print("NO, garbage terminator not found :(:(:(\n", .{});
    }
    const empty = try bip324Recv(&proxy_client, &bip324_ciphers, partner_garbage);
    defer std.heap.page_allocator.free(empty);
    std.debug.assert(empty.len == 1);
    try print("[=] Handshake phase finished, v2 connection established.\n", .{});
    try print("[=] Session ID: {x}\n", .{session_id});
    // - forward initial VERSION message
    try sendV2Message(&proxy_client, &bip324_ciphers, &first_msg);
    try print("initial VERSION message forwarded to remote.\n", .{});
    try mainLoop(proxy_server, &proxy_client, &bip324_ciphers);
}

fn mainLoop(local_connection: *const net.Stream, remote_connection: *const net.Stream,
            bip324_ciphers: *BIP324Ciphers) !void {
    // setup pollfd array
    var fds: [2]c.struct_pollfd = .{
        .{ .fd = local_connection.handle, .events = c.POLLIN, .revents = 0 },
        .{ .fd = remote_connection.handle, .events = c.POLLIN, .revents = 0 },
    };

    while (true) {
        const ret = c.poll(&fds[0], fds.len, 1000);
        if (ret == 0) {
            continue;
        } else if (ret < 0) {
            return error.PollFailed;
        }

        // forward [local] v1 ---> v2 [remote]
        if ((fds[0].revents & c.POLLIN) != 0) {
            const local_msg = try recvV1MessageFull(local_connection);
            defer std.heap.page_allocator.destroy(local_msg);
            try print("[-->] Received v1 \'{s}\', {d} bytes payload\n", .{local_msg.getMsgType(), local_msg.getPayload().len});
            try sendV2Message(remote_connection, bip324_ciphers, local_msg);
        }

        // forward [local] v1 <--- v2 [remote]
        if ((fds[1].revents & c.POLLIN) != 0) {
            const remote_msg = try recvV2Message(remote_connection, bip324_ciphers);
            defer std.heap.page_allocator.destroy(remote_msg);
            try print("[<--] Received v2 \'{s}\', {d} bytes payload\n", .{remote_msg.getMsgType(), remote_msg.getPayload().len});
            try sendV1Message(local_connection, remote_msg);
        }
    }
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

    pub fn setKey(ch: *ChaCha20, key: [32]u8) void {
        ch.key = key;
        ch.bufleft = 0;
    }

    pub fn seek(ch: *ChaCha20, nonce: [12]u8, block_counter: u32) void {
        ch.nonce = nonce;
        ch.block_counter = block_counter;
        ch.bufleft = 0;
    }

    pub fn crypt(ch: *ChaCha20, in_: []const u8, out_: []u8) void {
        var in = in_;
        var out = out_;
        std.debug.assert(in.len == out.len);

        if (in.len == 0) return;
        if (ch.bufleft > 0) {
            const reuse = @min(ch.bufleft, in.len);
            for (0..reuse) |i| {
                out[i] = in[i] ^ ch.buffer[64 - ch.bufleft + i];
            }
            ch.bufleft -= reuse;
            out = out[reuse..];
            in = in[reuse..];
        }
        if (in.len >= 64) {
            const blocks: u64 = in.len / 64;
            chacha.ChaCha20IETF.xor(out[0 .. blocks * 64], in[0 .. blocks * 64], ch.block_counter, ch.key, ch.nonce);
            ch.block_counter += @intCast(blocks);
            out = out[64 * blocks ..];
            in = in[64 * blocks ..];
        }
        if (in.len > 0) {
            chacha.ChaCha20IETF.stream(&ch.buffer, ch.block_counter, ch.key, ch.nonce);
            ch.block_counter += 1;
            for (0..in.len) |i| {
                out[i] = in[i] ^ ch.buffer[i];
            }
            ch.bufleft = 64 - in.len;
        }
    }

    pub fn stream(ch: *ChaCha20, out_: []u8) void {
        var out = out_;
        if (out.len == 0) return;
        if (ch.bufleft > 0) {
            const reuse = @min(ch.bufleft, out.len);
            @memcpy(out[0..reuse], ch.buffer[ch.buffer.len - ch.bufleft .. ch.buffer.len - ch.bufleft + reuse]);
            ch.bufleft -= reuse;
            out = out[reuse..];
        }
        if (out.len >= 64) {
            const blocks = out.len / 64;
            chacha.ChaCha20IETF.stream(out[0 .. blocks * 64], ch.block_counter, ch.key, ch.nonce);
            ch.block_counter += @intCast(blocks);
            out = out[64 * blocks ..];
        }
        if (out.len > 0) {
            chacha.ChaCha20IETF.stream(&ch.buffer, ch.block_counter, ch.key, ch.nonce);
            ch.block_counter += 1;
            @memcpy(out, ch.buffer[0 .. out.len]);
            ch.bufleft = 64 - out.len;
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

    pub fn decrypt(a: *AEADChaCha20Poly1305, cipher: []u8, aad: []const u8, nonce: [12]u8, plain1: []u8, plain2: []u8) bool {
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

    pub fn decrypt(fscp: *FSChaCha20Poly1305, cipher: []u8, aad: []const u8, plain1: []u8, plain2: []u8) bool {
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

    const server_addr = try net.Address.parseIp4("127.0.0.1", BIP324_PROXY_PORT);
    var server = try server_addr.listen(.{.reuse_address = true});
    defer server.deinit();
    try print("Waiting for incoming v1 connections on {f}...\n", .{server.listen_address});

    while (true) {
        const proxy_server = try server.accept();
        defer proxy_server.stream.close();
        try print("[<] New connection from {f}\n", .{proxy_server.address});
        // TODO: start this up in a new thread
        bip324ProxyHandler(&proxy_server.stream) catch {
            try print("Connection was closed.\n", .{});
        };
    }
}
