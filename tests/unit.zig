const std = @import("std");
const sshca = @import("sshca");
const fixtures = @import("fixtures");

test "RSA authorized key fixture parses and round trips" {
    var key = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer key.deinit(std.testing.allocator);

    try std.testing.expectEqual(sshca.SubjectAlgorithm.rsa, key.algorithm());
    try std.testing.expectEqualStrings("user@domain.local", key.comment().?);

    const formatted = try key.formatAuthorizedKey(std.testing.allocator);
    defer std.testing.allocator.free(formatted);
    try std.testing.expectEqualStrings(
        std.mem.trim(u8, fixtures.rsa_authorized_key, " \t\r\n"),
        formatted,
    );
}

test "Ed25519 authorized key fixture parses and round trips" {
    var key = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.ed25519_authorized_key);
    defer key.deinit(std.testing.allocator);

    try std.testing.expectEqual(sshca.SubjectAlgorithm.ed25519, key.algorithm());
    const formatted = try key.formatAuthorizedKey(std.testing.allocator);
    defer std.testing.allocator.free(formatted);
    try std.testing.expectEqualStrings(
        std.mem.trim(u8, fixtures.ed25519_authorized_key, " \t\r\n"),
        formatted,
    );
}

test "authorized key preserves a multiword comment" {
    var key = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.rsa_authorized_key_long_comment,
    );
    defer key.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "user@domain.local comment can be many words",
        key.comment().?,
    );
    const formatted = try key.formatAuthorizedKey(std.testing.allocator);
    defer std.testing.allocator.free(formatted);
    try std.testing.expectEqualStrings(
        std.mem.trim(u8, fixtures.rsa_authorized_key_long_comment, " \t\r\n"),
        formatted,
    );
}

test "PKCS#1 and SPKI PEM fixtures match the authorized RSA key" {
    var authorized = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.rsa_authorized_key,
    );
    defer authorized.deinit(std.testing.allocator);
    var pkcs1 = try sshca.parseRsaPublicKeyPem(
        std.testing.allocator,
        fixtures.rsa_public_key_pkcs1_pem,
        null,
    );
    defer pkcs1.deinit(std.testing.allocator);
    var spki = try sshca.parseRsaPublicKeyPem(
        std.testing.allocator,
        fixtures.rsa_public_key_spki_pem,
        null,
    );
    defer spki.deinit(std.testing.allocator);

    const expected = authorized.rsa;
    try expectSameRsa(expected, pkcs1.rsa);
    try expectSameRsa(expected, spki.rsa);
    try authorized.validateRsaMinimumBits(2048);
    try std.testing.expectError(error.RsaKeyTooSmall, authorized.validateRsaMinimumBits(4096));
}

test "Key Vault JWK n and e bytes format as the equivalent OpenSSH key" {
    var parsed = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer parsed.deinit(std.testing.allocator);
    const rsa = parsed.rsa;

    var from_jwk = try sshca.PublicKey.initRsa(
        std.testing.allocator,
        rsa.exponent,
        rsa.modulus,
        null,
    );
    defer from_jwk.deinit(std.testing.allocator);

    const parsed_blob = try parsed.authorizedKeyBlob(std.testing.allocator);
    defer std.testing.allocator.free(parsed_blob);
    const jwk_blob = try from_jwk.authorizedKeyBlob(std.testing.allocator);
    defer std.testing.allocator.free(jwk_blob);
    try std.testing.expectEqualSlices(u8, parsed_blob, jwk_blob);
}

test "fingerprint and cert-authority formats use OpenSSH syntax" {
    var key = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer key.deinit(std.testing.allocator);

    const fingerprint = try key.fingerprintSha256(std.testing.allocator);
    defer std.testing.allocator.free(fingerprint);
    try std.testing.expectEqualStrings(
        "SHA256:FjjMzZVSerCHx3LNZhoanmozlac3zyeRvbhGkf1izGo",
        fingerprint,
    );

    const line = try key.formatCertAuthority(std.testing.allocator);
    defer std.testing.allocator.free(line);
    try std.testing.expect(std.mem.startsWith(u8, line, "cert-authority ssh-rsa "));
}

test "authorized key parser rejects mismatched algorithms and oversized input" {
    const rsa = std.mem.trim(u8, fixtures.rsa_authorized_key, " \t\r\n");
    const separator = std.mem.indexOfScalar(u8, rsa, ' ').?;
    const mismatched = try std.fmt.allocPrint(
        std.testing.allocator,
        "ssh-ed25519{s}",
        .{rsa[separator..]},
    );
    defer std.testing.allocator.free(mismatched);
    try std.testing.expectError(
        error.AlgorithmMismatch,
        sshca.parseAuthorizedKey(std.testing.allocator, mismatched),
    );

    const oversized = try std.testing.allocator.alloc(
        u8,
        sshca.public_key.max_authorized_key_len + 1,
    );
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'a');
    try std.testing.expectError(
        error.AuthorizedKeyTooLarge,
        sshca.parseAuthorizedKey(std.testing.allocator, oversized),
    );
}

test "authorized key parser rejects malformed RSA mpints and trailing data" {
    const cases = [_]struct {
        exponent: []const u8,
        expected_error: anyerror,
    }{
        .{ .exponent = &.{0x80}, .expected_error = error.NegativeInteger },
        .{ .exponent = &.{ 0, 1 }, .expected_error = error.NonCanonicalInteger },
        .{ .exponent = &.{}, .expected_error = error.ZeroInteger },
    };
    for (cases) |case| {
        const line = try formatRsaLine(std.testing.allocator, case.exponent, &.{5}, "");
        defer std.testing.allocator.free(line);
        try std.testing.expectError(
            case.expected_error,
            sshca.parseAuthorizedKey(std.testing.allocator, line),
        );
    }

    const trailing = try formatRsaLine(std.testing.allocator, &.{3}, &.{5}, &.{0});
    defer std.testing.allocator.free(trailing);
    try std.testing.expectError(
        error.TrailingData,
        sshca.parseAuthorizedKey(std.testing.allocator, trailing),
    );
}

test "constructors and PEM parsing reject comment line injection" {
    try std.testing.expectError(
        error.CommentContainsLineBreak,
        sshca.PublicKey.initEd25519(std.testing.allocator, &([_]u8{1} ** 32), "safe\nssh-rsa"),
    );
    try std.testing.expectError(
        error.CommentContainsLineBreak,
        sshca.parseRsaPublicKeyPem(
            std.testing.allocator,
            fixtures.rsa_public_key_pkcs1_pem,
            "safe\runsafe",
        ),
    );
}

test "PEM parser rejects private and encrypted key labels" {
    try std.testing.expectError(
        error.UnsupportedPemType,
        sshca.parseRsaPublicKeyPem(
            std.testing.allocator,
            "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----",
            null,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedPemType,
        sshca.parseRsaPublicKeyPem(
            std.testing.allocator,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----",
            null,
        ),
    );
}

test "PEM parser rejects malformed DER through the public API" {
    const cases = [_]struct {
        der: []const u8,
        expected_error: anyerror,
    }{
        .{
            .der = &.{ 0x30, 0x80 },
            .expected_error = error.IndefiniteDerLength,
        },
        .{
            .der = &.{ 0x30, 0x81, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03 },
            .expected_error = error.NonCanonicalDerLength,
        },
        .{
            .der = &.{ 0x30, 0x06, 0x02, 0x01, 0x85, 0x02, 0x01, 0x03 },
            .expected_error = error.NegativeInteger,
        },
        .{
            .der = &.{ 0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x03 },
            .expected_error = error.NonCanonicalInteger,
        },
        .{
            .der = &.{ 0x30, 0x07, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03, 0x00 },
            .expected_error = error.TrailingDerData,
        },
        .{
            .der = &.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03, 0x00 },
            .expected_error = error.TrailingDerData,
        },
    };

    for (cases) |case| {
        const pem = try formatPkcs1Pem(std.testing.allocator, case.der);
        defer std.testing.allocator.free(pem);
        try std.testing.expectError(
            case.expected_error,
            sshca.parseRsaPublicKeyPem(std.testing.allocator, pem, null),
        );
    }
}

test "SPKI parser rejects an unexpected OID and invalid bit string" {
    const valid_spki = [_]u8{
        0x30, 0x1a,
        0x30, 0x0d,
        0x06, 0x09,
        0x2a, 0x86,
        0x48, 0x86,
        0xf7, 0x0d,
        0x01, 0x01,
        0x01, 0x05,
        0x00, 0x03,
        0x09, 0x00,
        0x30, 0x06,
        0x02, 0x01,
        0x05, 0x02,
        0x01, 0x03,
    };

    var bad_oid = valid_spki;
    bad_oid[14] = 0x02;
    const bad_oid_pem = try formatPem(std.testing.allocator, "PUBLIC KEY", &bad_oid);
    defer std.testing.allocator.free(bad_oid_pem);
    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        sshca.parseRsaPublicKeyPem(std.testing.allocator, bad_oid_pem, null),
    );

    var bad_bit_string = valid_spki;
    bad_bit_string[19] = 1;
    const bad_bit_string_pem = try formatPem(
        std.testing.allocator,
        "PUBLIC KEY",
        &bad_bit_string,
    );
    defer std.testing.allocator.free(bad_bit_string_pem);
    try std.testing.expectError(
        error.InvalidBitString,
        sshca.parseRsaPublicKeyPem(std.testing.allocator, bad_bit_string_pem, null),
    );
}

fn expectSameRsa(expected: sshca.public_key.Rsa, actual: sshca.public_key.Rsa) !void {
    try std.testing.expectEqualSlices(u8, expected.exponent, actual.exponent);
    try std.testing.expectEqualSlices(u8, expected.modulus, actual.modulus);
}

fn formatRsaLine(
    allocator: std.mem.Allocator,
    exponent: []const u8,
    modulus: []const u8,
    trailing: []const u8,
) ![]u8 {
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(allocator);
    try appendSshString(allocator, &blob, "ssh-rsa");
    try appendSshString(allocator, &blob, exponent);
    try appendSshString(allocator, &blob, modulus);
    try blob.appendSlice(allocator, trailing);

    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(blob.items.len));
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, blob.items);
    return std.fmt.allocPrint(allocator, "ssh-rsa {s}", .{encoded});
}

fn appendSshString(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    value: []const u8,
) !void {
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, length[0..], @intCast(value.len), .big);
    try output.appendSlice(allocator, &length);
    try output.appendSlice(allocator, value);
}

fn formatPkcs1Pem(allocator: std.mem.Allocator, der: []const u8) ![]u8 {
    return formatPem(allocator, "RSA PUBLIC KEY", der);
}

fn formatPem(
    allocator: std.mem.Allocator,
    label: []const u8,
    der: []const u8,
) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(der.len));
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, der);
    return std.fmt.allocPrint(
        allocator,
        "-----BEGIN {s}-----\n{s}\n-----END {s}-----",
        .{ label, encoded, label },
    );
}
