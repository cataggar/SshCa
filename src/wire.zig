const std = @import("std");

pub const default_max_blob_len: usize = 10 * 1024 * 1024;

pub const Reader = struct {
    data: []const u8,
    position: usize = 0,
    max_blob_len: usize = default_max_blob_len,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn initWithLimit(data: []const u8, max_blob_len: usize) Reader {
        return .{
            .data = data,
            .max_blob_len = @min(max_blob_len, default_max_blob_len),
        };
    }

    pub fn remaining(self: Reader) usize {
        return self.data.len - self.position;
    }

    pub fn readRaw(self: *Reader, count: usize) ![]const u8 {
        if (count > self.remaining()) return error.EndOfBuffer;
        const start = self.position;
        self.position += count;
        return self.data[start..self.position];
    }

    pub fn readU32(self: *Reader) !u32 {
        const bytes = try self.readRaw(4);
        return std.mem.readInt(u32, bytes[0..4], .big);
    }

    pub fn readU64(self: *Reader) !u64 {
        const bytes = try self.readRaw(8);
        return std.mem.readInt(u64, bytes[0..8], .big);
    }

    pub fn readI64(self: *Reader) !i64 {
        return @bitCast(try self.readU64());
    }

    pub fn readString(self: *Reader) ![]const u8 {
        const length = try self.readU32();
        const length_usize: usize = @intCast(length);
        if (length_usize > self.max_blob_len) return error.BlobTooLarge;
        return self.readRaw(length_usize);
    }

    pub fn readNested(self: *Reader) !Reader {
        return Reader.initWithLimit(try self.readString(), self.max_blob_len);
    }

    pub fn expectEnd(self: Reader) !void {
        if (self.remaining() != 0) return error.TrailingData;
    }
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) Writer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Writer) void {
        self.bytes.deinit(self.allocator);
    }

    pub fn items(self: Writer) []const u8 {
        return self.bytes.items;
    }

    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.bytes.toOwnedSlice(self.allocator);
    }

    pub fn writeRaw(self: *Writer, value: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, value);
    }

    pub fn writeU32(self: *Writer, value: u32) !void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, bytes[0..], value, .big);
        try self.writeRaw(&bytes);
    }

    pub fn writeU64(self: *Writer, value: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, bytes[0..], value, .big);
        try self.writeRaw(&bytes);
    }

    pub fn writeI64(self: *Writer, value: i64) !void {
        try self.writeU64(@bitCast(value));
    }

    pub fn writeString(self: *Writer, value: []const u8) !void {
        if (value.len > default_max_blob_len) return error.BlobTooLarge;
        if (value.len > std.math.maxInt(u32)) return error.LengthOverflow;
        try self.writeU32(@intCast(value.len));
        try self.writeRaw(value);
    }

    pub fn writeNested(self: *Writer, nested: Writer) !void {
        try self.writeString(nested.items());
    }

    pub fn writePositiveMpint(self: *Writer, unsigned_value: []const u8) !void {
        try validateCanonicalUnsigned(unsigned_value);
        const needs_zero_prefix = unsigned_value[0] & 0x80 != 0;
        if (unsigned_value.len > default_max_blob_len - @intFromBool(needs_zero_prefix)) {
            return error.BlobTooLarge;
        }
        const encoded_len = unsigned_value.len + @intFromBool(needs_zero_prefix);

        try self.writeU32(@intCast(encoded_len));
        if (needs_zero_prefix) try self.writeRaw(&.{0});
        try self.writeRaw(unsigned_value);
    }
};

pub fn readPositiveMpint(encoded: []const u8) ![]const u8 {
    if (encoded.len == 0) return error.ZeroInteger;
    if (encoded[0] & 0x80 != 0) return error.NegativeInteger;
    if (encoded[0] != 0) return encoded;
    if (encoded.len == 1) return error.ZeroInteger;
    if (encoded[1] & 0x80 == 0) return error.NonCanonicalInteger;
    return encoded[1..];
}

pub fn validateCanonicalUnsigned(value: []const u8) !void {
    if (value.len == 0) return error.ZeroInteger;
    if (value[0] == 0) return error.NonCanonicalInteger;
}

test "wire integers and strings round trip" {
    var writer = Writer.init(std.testing.allocator);
    defer writer.deinit();
    try writer.writeU32(0x01020304);
    try writer.writeU64(0x0102030405060708);
    try writer.writeI64(-2);
    try writer.writeString("ssh-rsa");

    var reader = Reader.init(writer.items());
    try std.testing.expectEqual(@as(u32, 0x01020304), try reader.readU32());
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), try reader.readU64());
    try std.testing.expectEqual(@as(i64, -2), try reader.readI64());
    try std.testing.expectEqualStrings("ssh-rsa", try reader.readString());
    try reader.expectEnd();
}

test "wire reader rejects truncation, oversized blobs, and trailing data" {
    var truncated = Reader.init(&.{ 0, 0, 0 });
    try std.testing.expectError(error.EndOfBuffer, truncated.readU32());

    var oversized = Reader.initWithLimit(&.{ 0, 0, 0, 2, 1, 2 }, 1);
    try std.testing.expectError(error.BlobTooLarge, oversized.readString());

    var above_absolute_ceiling = Reader.initWithLimit(
        &.{ 0, 0xa0, 0, 1 },
        std.math.maxInt(usize),
    );
    try std.testing.expectError(error.BlobTooLarge, above_absolute_ceiling.readString());

    var trailing = Reader.init(&.{1});
    try std.testing.expectError(error.TrailingData, trailing.expectEnd());
}

test "positive mpint canonicalization" {
    try std.testing.expectEqualSlices(u8, &.{0x80}, try readPositiveMpint(&.{ 0, 0x80 }));
    try std.testing.expectEqualSlices(u8, &.{0x7f}, try readPositiveMpint(&.{0x7f}));
    try std.testing.expectError(error.NegativeInteger, readPositiveMpint(&.{0x80}));
    try std.testing.expectError(error.NonCanonicalInteger, readPositiveMpint(&.{ 0, 1 }));
    try std.testing.expectError(error.ZeroInteger, readPositiveMpint(&.{}));
}

test "positive mpint writer adds a sign byte only when required" {
    var writer = Writer.init(std.testing.allocator);
    defer writer.deinit();
    try writer.writePositiveMpint(&.{0x80});
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 2, 0, 0x80 }, writer.items());
}
