const std = @import("std");
const wire = @import("wire.zig");

pub const max_authorized_key_len: usize = 10_000;
const max_decoded_key_blob_len: usize = max_authorized_key_len;

pub const Algorithm = enum {
    rsa,
    ed25519,

    pub fn sshName(self: Algorithm) []const u8 {
        return switch (self) {
            .rsa => "ssh-rsa",
            .ed25519 => "ssh-ed25519",
        };
    }
};

pub const Rsa = struct {
    exponent: []u8,
    modulus: []u8,
    comment: ?[]u8,
};

pub const Ed25519 = struct {
    key: [32]u8,
    comment: ?[]u8,
};

pub const PublicKey = union(Algorithm) {
    rsa: Rsa,
    ed25519: Ed25519,

    pub fn initRsa(
        allocator: std.mem.Allocator,
        exponent: []const u8,
        modulus: []const u8,
        comment_value: ?[]const u8,
    ) !PublicKey {
        try wire.validateCanonicalUnsigned(exponent);
        try wire.validateCanonicalUnsigned(modulus);
        try validateRsaValues(exponent, modulus);

        const owned_exponent = try allocator.dupe(u8, exponent);
        errdefer allocator.free(owned_exponent);
        const owned_modulus = try allocator.dupe(u8, modulus);
        errdefer allocator.free(owned_modulus);
        const owned_comment = try copyComment(allocator, comment_value);
        errdefer if (owned_comment) |value| allocator.free(value);

        return .{ .rsa = .{
            .exponent = owned_exponent,
            .modulus = owned_modulus,
            .comment = owned_comment,
        } };
    }

    pub fn initEd25519(
        allocator: std.mem.Allocator,
        key: []const u8,
        comment_value: ?[]const u8,
    ) !PublicKey {
        if (key.len != 32) return error.InvalidEd25519Length;
        const owned_comment = try copyComment(allocator, comment_value);
        errdefer if (owned_comment) |value| allocator.free(value);

        return .{ .ed25519 = .{
            .key = key[0..32].*,
            .comment = owned_comment,
        } };
    }

    pub fn deinit(self: *PublicKey, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .rsa => |rsa| {
                allocator.free(rsa.exponent);
                allocator.free(rsa.modulus);
                if (rsa.comment) |comment_value| allocator.free(comment_value);
            },
            .ed25519 => |ed25519| {
                if (ed25519.comment) |comment_value| allocator.free(comment_value);
            },
        }
    }

    pub fn algorithm(self: PublicKey) Algorithm {
        return std.meta.activeTag(self);
    }

    pub fn comment(self: PublicKey) ?[]const u8 {
        return switch (self) {
            .rsa => |rsa| rsa.comment,
            .ed25519 => |ed25519| ed25519.comment,
        };
    }

    pub fn authorizedKeyBlob(self: PublicKey, allocator: std.mem.Allocator) ![]u8 {
        var writer = wire.Writer.init(allocator);
        defer writer.deinit();

        switch (self) {
            .rsa => |rsa| {
                try writer.writeString(Algorithm.rsa.sshName());
                try writer.writePositiveMpint(rsa.exponent);
                try writer.writePositiveMpint(rsa.modulus);
            },
            .ed25519 => |ed25519| {
                try writer.writeString(Algorithm.ed25519.sshName());
                try writer.writeString(&ed25519.key);
            },
        }

        return writer.toOwnedSlice();
    }

    pub fn formatAuthorizedKey(self: PublicKey, allocator: std.mem.Allocator) ![]u8 {
        const blob = try self.authorizedKeyBlob(allocator);
        defer allocator.free(blob);

        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(blob.len));
        defer allocator.free(encoded);
        _ = encoder.encode(encoded, blob);

        if (self.comment()) |comment_value| {
            return std.fmt.allocPrint(
                allocator,
                "{s} {s} {s}",
                .{ self.algorithm().sshName(), encoded, comment_value },
            );
        }
        return std.fmt.allocPrint(
            allocator,
            "{s} {s}",
            .{ self.algorithm().sshName(), encoded },
        );
    }

    pub fn formatCertAuthority(self: PublicKey, allocator: std.mem.Allocator) ![]u8 {
        const authorized_key = try self.formatAuthorizedKey(allocator);
        defer allocator.free(authorized_key);
        return std.fmt.allocPrint(allocator, "cert-authority {s}", .{authorized_key});
    }

    pub fn fingerprintSha256(self: PublicKey, allocator: std.mem.Allocator) ![]u8 {
        const blob = try self.authorizedKeyBlob(allocator);
        defer allocator.free(blob);

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(blob, &digest, .{});

        const encoder = std.base64.standard_no_pad.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(digest.len));
        defer allocator.free(encoded);
        _ = encoder.encode(encoded, &digest);
        return std.fmt.allocPrint(allocator, "SHA256:{s}", .{encoded});
    }

    pub fn rsaModulusBits(self: PublicKey) !usize {
        const modulus = switch (self) {
            .rsa => |rsa| rsa.modulus,
            .ed25519 => return error.NotRsaKey,
        };
        return (modulus.len - 1) * 8 + (8 - @as(usize, @intCast(@clz(modulus[0]))));
    }

    pub fn validateRsaMinimumBits(self: PublicKey, minimum_bits: usize) !void {
        if (try self.rsaModulusBits() < minimum_bits) return error.RsaKeyTooSmall;
    }
};

pub fn parseAuthorizedKey(allocator: std.mem.Allocator, input: []const u8) !PublicKey {
    if (input.len > max_authorized_key_len) return error.AuthorizedKeyTooLarge;
    if (std.mem.indexOfScalar(u8, input, 0) != null) return error.NullByte;

    const line = std.mem.trim(u8, input, " \t\r\n");
    if (line.len == 0) return error.EmptyAuthorizedKey;
    if (std.mem.indexOfAny(u8, line, "\r\n") != null) return error.MalformedAuthorizedKey;

    const fields = try splitAuthorizedKey(line);
    const decoder = if (std.mem.endsWith(u8, fields.encoded, "="))
        std.base64.standard.Decoder
    else
        std.base64.standard_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(fields.encoded) catch
        return error.InvalidBase64;
    if (decoded_len > max_decoded_key_blob_len) return error.KeyBlobTooLarge;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    decoder.decode(decoded, fields.encoded) catch return error.InvalidBase64;

    var reader = wire.Reader.initWithLimit(decoded, max_decoded_key_blob_len);
    const embedded_algorithm = try reader.readString();
    if (!std.mem.eql(u8, fields.algorithm, embedded_algorithm)) {
        return error.AlgorithmMismatch;
    }

    if (std.mem.eql(u8, embedded_algorithm, Algorithm.rsa.sshName())) {
        const exponent = try wire.readPositiveMpint(try reader.readString());
        const modulus = try wire.readPositiveMpint(try reader.readString());
        try reader.expectEnd();
        return PublicKey.initRsa(allocator, exponent, modulus, fields.comment);
    }
    if (std.mem.eql(u8, embedded_algorithm, Algorithm.ed25519.sshName())) {
        const key = try reader.readString();
        try reader.expectEnd();
        return PublicKey.initEd25519(allocator, key, fields.comment);
    }
    return error.UnsupportedAlgorithm;
}

const AuthorizedKeyFields = struct {
    algorithm: []const u8,
    encoded: []const u8,
    comment: ?[]const u8,
};

fn splitAuthorizedKey(line: []const u8) !AuthorizedKeyFields {
    var position: usize = 0;
    const algorithm = nextField(line, &position) orelse return error.MalformedAuthorizedKey;
    const encoded = nextField(line, &position) orelse return error.MalformedAuthorizedKey;
    skipHorizontalWhitespace(line, &position);
    const comment = if (position < line.len)
        std.mem.trimEnd(u8, line[position..], " \t")
    else
        null;

    return .{
        .algorithm = algorithm,
        .encoded = encoded,
        .comment = comment,
    };
}

fn nextField(line: []const u8, position: *usize) ?[]const u8 {
    skipHorizontalWhitespace(line, position);
    if (position.* == line.len) return null;
    const start = position.*;
    while (position.* < line.len and !isHorizontalWhitespace(line[position.*])) {
        position.* += 1;
    }
    return line[start..position.*];
}

fn skipHorizontalWhitespace(line: []const u8, position: *usize) void {
    while (position.* < line.len and isHorizontalWhitespace(line[position.*])) {
        position.* += 1;
    }
}

fn isHorizontalWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

fn copyComment(
    allocator: std.mem.Allocator,
    comment: ?[]const u8,
) !?[]u8 {
    const value = comment orelse return null;
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.NullByte;
    if (std.mem.indexOfAny(u8, value, "\r\n") != null) {
        return error.CommentContainsLineBreak;
    }
    if (value.len == 0) return null;
    return try allocator.dupe(u8, value);
}

fn validateRsaValues(exponent: []const u8, modulus: []const u8) !void {
    if (exponent[exponent.len - 1] & 1 == 0) return error.InvalidRsaExponent;
    if (exponent.len == 1 and exponent[0] < 3) return error.InvalidRsaExponent;
    if (modulus[modulus.len - 1] & 1 == 0) return error.InvalidRsaModulus;
    if (compareUnsigned(exponent, modulus) != .lt) return error.InvalidRsaExponent;
}

fn compareUnsigned(left: []const u8, right: []const u8) std.math.Order {
    if (left.len < right.len) return .lt;
    if (left.len > right.len) return .gt;
    return std.mem.order(u8, left, right);
}

test "ed25519 constructor enforces the key length" {
    try std.testing.expectError(
        error.InvalidEd25519Length,
        PublicKey.initEd25519(std.testing.allocator, &.{1}, null),
    );
}

test "RSA constructor rejects unsafe public values" {
    try std.testing.expectError(
        error.InvalidRsaExponent,
        PublicKey.initRsa(std.testing.allocator, &.{1}, &.{5}, null),
    );
    try std.testing.expectError(
        error.InvalidRsaExponent,
        PublicKey.initRsa(std.testing.allocator, &.{4}, &.{5}, null),
    );
    try std.testing.expectError(
        error.InvalidRsaModulus,
        PublicKey.initRsa(std.testing.allocator, &.{3}, &.{6}, null),
    );
}
