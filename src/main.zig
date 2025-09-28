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
    }
}
