const std = @import("std");
const net = std.net;

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
}
