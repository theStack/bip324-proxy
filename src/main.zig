const std = @import("std");
const hmac = std.crypto.auth.hmac; // TODO: needed?
const hkdf = std.crypto.kdf.hkdf;
const net = std.net;
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
    _ = initiator_L;
    _ = initiator_P;
    _ = responder_L;
    _ = responder_P;
    _ = garbage_terminators;
}

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
        bip324ProxyHandler(&proxy_server) catch {
            try print("Connection was closed.\n", .{});
        };
    }
}
