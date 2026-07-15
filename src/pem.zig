const std = @import("std");
const public_key = @import("public_key.zig");

pub const max_pem_len: usize = 1 * 1024 * 1024;
pub const max_der_len: usize = 256 * 1024;

const rsa_public_key_header = "-----BEGIN RSA PUBLIC KEY-----";
const rsa_public_key_footer = "-----END RSA PUBLIC KEY-----";
const public_key_header = "-----BEGIN PUBLIC KEY-----";
const public_key_footer = "-----END PUBLIC KEY-----";
const rsa_encryption_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

pub fn parseRsaPublicKey(
    allocator: std.mem.Allocator,
    pem: []const u8,
    comment: ?[]const u8,
) !public_key.PublicKey {
    if (pem.len > max_pem_len) return error.PemTooLarge;
    if (std.mem.indexOfScalar(u8, pem, 0) != null) return error.NullByte;

    const trimmed = std.mem.trim(u8, pem, " \t\r\n");
    if (std.mem.startsWith(u8, trimmed, rsa_public_key_header)) {
        const der = try decodePem(
            allocator,
            trimmed,
            rsa_public_key_header,
            rsa_public_key_footer,
        );
        defer allocator.free(der);
        return parsePkcs1Der(allocator, der, comment);
    }
    if (std.mem.startsWith(u8, trimmed, public_key_header)) {
        const der = try decodePem(
            allocator,
            trimmed,
            public_key_header,
            public_key_footer,
        );
        defer allocator.free(der);
        return parseSpkiDer(allocator, der, comment);
    }
    return error.UnsupportedPemType;
}

fn decodePem(
    allocator: std.mem.Allocator,
    pem: []const u8,
    header: []const u8,
    footer: []const u8,
) ![]u8 {
    if (!std.mem.endsWith(u8, pem, footer)) return error.InvalidPem;
    const body = pem[header.len .. pem.len - footer.len];
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const upper_bound = decoder.calcSizeUpperBound(body.len);
    if (upper_bound > max_der_len) return error.DerTooLarge;

    const decoded = try allocator.alloc(u8, upper_bound);
    errdefer allocator.free(decoded);
    const decoded_len = decoder.decode(decoded, body) catch return error.InvalidBase64;
    if (decoded_len > max_der_len) return error.DerTooLarge;
    return allocator.realloc(decoded, decoded_len);
}

fn parsePkcs1Der(
    allocator: std.mem.Allocator,
    der: []const u8,
    comment: ?[]const u8,
) !public_key.PublicKey {
    var outer = DerReader.init(der);
    var sequence = DerReader.init(try outer.readElement(0x30));
    try outer.expectEnd();

    const modulus = try readPositiveInteger(&sequence);
    const exponent = try readPositiveInteger(&sequence);
    try sequence.expectEnd();
    return public_key.PublicKey.initRsa(allocator, exponent, modulus, comment);
}

fn parseSpkiDer(
    allocator: std.mem.Allocator,
    der: []const u8,
    comment: ?[]const u8,
) !public_key.PublicKey {
    var outer = DerReader.init(der);
    var sequence = DerReader.init(try outer.readElement(0x30));
    try outer.expectEnd();

    var algorithm = DerReader.init(try sequence.readElement(0x30));
    const oid = try algorithm.readElement(0x06);
    if (!std.mem.eql(u8, oid, &rsa_encryption_oid)) return error.UnsupportedAlgorithm;
    const parameters = try algorithm.readElement(0x05);
    if (parameters.len != 0) return error.InvalidAlgorithmParameters;
    try algorithm.expectEnd();

    const bit_string = try sequence.readElement(0x03);
    if (bit_string.len == 0 or bit_string[0] != 0) return error.InvalidBitString;
    try sequence.expectEnd();
    return parsePkcs1Der(allocator, bit_string[1..], comment);
}

const DerReader = struct {
    data: []const u8,
    position: usize = 0,

    fn init(data: []const u8) DerReader {
        return .{ .data = data };
    }

    fn remaining(self: DerReader) usize {
        return self.data.len - self.position;
    }

    fn readByte(self: *DerReader) !u8 {
        if (self.position == self.data.len) return error.TruncatedDer;
        defer self.position += 1;
        return self.data[self.position];
    }

    fn readRaw(self: *DerReader, count: usize) ![]const u8 {
        if (count > self.remaining()) return error.TruncatedDer;
        const start = self.position;
        self.position += count;
        return self.data[start..self.position];
    }

    fn readElement(self: *DerReader, expected_tag: u8) ![]const u8 {
        const tag = try self.readByte();
        if (tag != expected_tag) return error.UnexpectedDerTag;
        const length = try self.readLength();
        return self.readRaw(length);
    }

    fn readLength(self: *DerReader) !usize {
        const first = try self.readByte();
        if (first < 0x80) return first;
        if (first == 0x80) return error.IndefiniteDerLength;

        const byte_count: usize = first & 0x7f;
        if (byte_count == 0 or byte_count > @sizeOf(usize)) {
            return error.DerLengthOverflow;
        }
        const encoded = try self.readRaw(byte_count);
        if (encoded[0] == 0) return error.NonCanonicalDerLength;

        var length: usize = 0;
        for (encoded) |byte| {
            const byte_value: usize = byte;
            if (length > (std.math.maxInt(usize) - byte_value) / 256) {
                return error.DerLengthOverflow;
            }
            length = length * 256 + byte_value;
        }
        if (length < 0x80) return error.NonCanonicalDerLength;
        if (length > max_der_len) return error.DerTooLarge;
        return length;
    }

    fn expectEnd(self: DerReader) !void {
        if (self.remaining() != 0) return error.TrailingDerData;
    }
};

fn readPositiveInteger(reader: *DerReader) ![]const u8 {
    const encoded = try reader.readElement(0x02);
    if (encoded.len == 0) return error.EmptyInteger;
    if (encoded[0] & 0x80 != 0) return error.NegativeInteger;
    if (encoded[0] != 0) return encoded;
    if (encoded.len == 1) return error.ZeroInteger;
    if (encoded[1] & 0x80 == 0) return error.NonCanonicalInteger;
    return encoded[1..];
}

test "DER parser rejects indefinite lengths" {
    var reader = DerReader.init(&.{ 0x30, 0x80 });
    try std.testing.expectError(error.IndefiniteDerLength, reader.readElement(0x30));
}
