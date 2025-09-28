const std = @import("std");
const net = std.net;

const BIP324_PROXY_PORT: u16 = 1324;
const NET_MAGIC: [4]u8 = .{0xf9,0xbe,0xb4,0xd9}; // mainnet
//const NET_MAGIC: [4]u8 = .{0x0a,0x03,0xcf,0x40}; // signet
const V1_PREFIX: [16]u8 = NET_MAGIC ++ .{'v','e','r','s','i','o','n',0,0,0,0,0};

var stdout_buf: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
const stdout = &stdout_writer.interface;

fn print(comptime fmt: []const u8, args: anytype) !void {
    try stdout.print(fmt, args);
    try stdout.flush();
}

fn bip324ProxyHandler(client: *const net.Server.Connection) !void {
    // peek into receiver buffer byte for byte to detect early if the first
    // incoming message is not a bitcoin p2p v1 message; in that case we can't
    // do anything (we wouldn't know the remote destination to send data to) and
    // have to close the local connection
    var received_prefix: [16]u8 = undefined;

    for (0..V1_PREFIX.len) |i| {
        var byte_buf: [1]u8 = undefined;
        const n_read = try client.stream.read(&byte_buf);
        if (n_read == 0) return error.ConnectionClosed;
        const byte = byte_buf[0];
        try print("byte read: {d}\n", .{byte});
        if (byte != V1_PREFIX[i]) {
            try print("V1 prefix mismatch after {d} bytes, close connection.\n", .{i+1});
            // TODO: show expected/received byte-strings
            return error.ConnectionClosed; // TODO: right error code?
        }
        received_prefix[i] = byte;
    }
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
        const client = try server.accept();
        defer client.stream.close();
        try print("[<] New connection from {f}\n", .{client.address});
        // TODO: start this up in a new thread
        try bip324ProxyHandler(&client);
    }
}
