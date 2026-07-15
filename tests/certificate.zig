const std = @import("std");
const sshca = @import("sshca");
const fixtures = @import("fixtures");

const principals = [_][]const u8{"someUser"};

const FakeSigner = struct {
    calls: usize = 0,
    signature_len: usize,
    signature_byte: u8 = 0xa5,
    digest: [64]u8 = undefined,

    fn digestSigner(self: *FakeSigner) sshca.DigestSigner {
        return sshca.DigestSigner.init(self, sign);
    }

    fn sign(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        digest: *const [64]u8,
    ) ![]u8 {
        const self: *FakeSigner = @ptrCast(@alignCast(context));
        self.calls += 1;
        self.digest = digest.*;
        const signature = try allocator.alloc(u8, self.signature_len);
        @memset(signature, self.signature_byte);
        return signature;
    }
};

test "deterministic request produces stable golden certificate bytes" {
    var ca = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer ca.deinit(std.testing.allocator);
    var subject = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.ed25519_authorized_key,
    );
    defer subject.deinit(std.testing.allocator);

    const request = makeRequest(&subject, &ca, &.{}, &.{}, "fixture-user");
    var fake = FakeSigner{ .signature_len = ca.rsa.modulus.len };
    const certificate = try (sshca.IssuancePolicy{}).issue(
        std.testing.allocator,
        request,
        fake.digestSigner(),
    );
    defer std.testing.allocator.free(certificate);

    var actual_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(certificate, &actual_hash, .{});
    const expected_hash = [_]u8{
        0x2d, 0xd7, 0x80, 0x41, 0x9b, 0x83, 0x1b, 0xab,
        0xbc, 0x9b, 0x5c, 0xcf, 0x33, 0x85, 0x37, 0x7c,
        0x83, 0x16, 0x7c, 0xdb, 0xb8, 0xa4, 0x20, 0x8d,
        0x50, 0x32, 0x9a, 0x7d, 0x2f, 0xf9, 0xbd, 0x26,
    };
    try std.testing.expectEqualSlices(u8, &expected_hash, &actual_hash);

    const to_be_signed = try sshca.certificate.buildToBeSigned(
        std.testing.allocator,
        request,
    );
    defer std.testing.allocator.free(to_be_signed);
    var expected_digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(to_be_signed, &expected_digest, .{});
    try std.testing.expectEqualSlices(u8, &expected_digest, &fake.digest);
}

test "RSA and Ed25519 subjects use their matching certificate algorithms" {
    var ca = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer ca.deinit(std.testing.allocator);
    var rsa = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer rsa.deinit(std.testing.allocator);
    var ed25519 = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.ed25519_authorized_key,
    );
    defer ed25519.deinit(std.testing.allocator);

    var rsa_fake = FakeSigner{ .signature_len = ca.rsa.modulus.len };
    const rsa_line = try (sshca.IssuancePolicy{}).issueAndFormat(
        std.testing.allocator,
        makeRequest(&rsa, &ca, &.{}, &.{}, null),
        rsa_fake.digestSigner(),
    );
    defer std.testing.allocator.free(rsa_line);
    try std.testing.expect(std.mem.startsWith(
        u8,
        rsa_line,
        sshca.certificate.rsa_certificate_algorithm ++ " ",
    ));

    var ed_fake = FakeSigner{ .signature_len = ca.rsa.modulus.len };
    const ed_line = try (sshca.IssuancePolicy{}).issueAndFormat(
        std.testing.allocator,
        makeRequest(&ed25519, &ca, &.{}, &.{}, null),
        ed_fake.digestSigner(),
    );
    defer std.testing.allocator.free(ed_line);
    try std.testing.expect(std.mem.startsWith(
        u8,
        ed_line,
        sshca.certificate.ed25519_certificate_algorithm ++ " ",
    ));
}

test "critical options and extensions are sorted and correctly nested" {
    var ca = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer ca.deinit(std.testing.allocator);
    var subject = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.ed25519_authorized_key,
    );
    defer subject.deinit(std.testing.allocator);

    const critical_options = [_]sshca.certificate.CriticalOption{
        .{ .source_address = fixtures.source_address },
        .{ .force_command = fixtures.force_command },
    };
    const extensions = [_]sshca.certificate.Extension{
        .permit_user_rc,
        .permit_pty,
        .permit_port_forwarding,
        .permit_agent_forwarding,
        .permit_x11_forwarding,
        .{ .custom = .{
            .name = "z-custom",
            .value = &.{ 0, 1, 2 },
        } },
    };
    const request = makeRequest(
        &subject,
        &ca,
        &critical_options,
        &extensions,
        null,
    );
    const encoded = try sshca.certificate.buildToBeSigned(
        std.testing.allocator,
        request,
    );
    defer std.testing.allocator.free(encoded);

    var reader = TestReader{ .data = encoded };
    try std.testing.expectEqualStrings(
        sshca.certificate.ed25519_certificate_algorithm,
        try reader.readString(),
    );
    _ = try reader.readString();
    _ = try reader.readString();
    _ = try reader.readU64();
    _ = try reader.readU32();
    _ = try reader.readString();
    _ = try reader.readString();
    _ = try reader.readU64();
    _ = try reader.readU64();

    var critical_reader = TestReader{ .data = try reader.readString() };
    try std.testing.expectEqualStrings("force-command", try critical_reader.readString());
    var force_command = TestReader{ .data = try critical_reader.readString() };
    try std.testing.expectEqualStrings(fixtures.force_command, try force_command.readString());
    try force_command.expectEnd();
    try std.testing.expectEqualStrings("source-address", try critical_reader.readString());
    var source_address = TestReader{ .data = try critical_reader.readString() };
    try std.testing.expectEqualStrings(fixtures.source_address, try source_address.readString());
    try source_address.expectEnd();
    try critical_reader.expectEnd();

    var extension_reader = TestReader{ .data = try reader.readString() };
    const expected_extensions = [_][]const u8{
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    };
    for (expected_extensions) |expected_name| {
        try std.testing.expectEqualStrings(expected_name, try extension_reader.readString());
        try std.testing.expectEqual(@as(usize, 0), (try extension_reader.readString()).len);
    }
    try std.testing.expectEqualStrings("z-custom", try extension_reader.readString());
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, try extension_reader.readString());
    try extension_reader.expectEnd();
}

test "invalid requests fail before the signer is called" {
    var ca = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer ca.deinit(std.testing.allocator);
    var subject = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.ed25519_authorized_key,
    );
    defer subject.deinit(std.testing.allocator);

    var fake = FakeSigner{ .signature_len = ca.rsa.modulus.len };
    var request = makeRequest(&subject, &ca, &.{}, &.{}, null);
    request.nonce = &([_]u8{0} ** 31);
    try std.testing.expectError(
        error.InvalidNonceLength,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fake.calls);

    request = makeRequest(&subject, &ca, &.{}, &.{}, null);
    request.validity.valid_before = request.validity.valid_after;
    try std.testing.expectError(
        error.InvalidValidity,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    request = makeRequest(&subject, &ca, &.{}, &.{}, null);
    request.principals = &.{};
    try std.testing.expectError(
        error.MissingPrincipals,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    const duplicates = [_]sshca.certificate.CriticalOption{
        .{ .force_command = "/bin/true" },
        .{ .force_command = "/bin/false" },
    };
    request = makeRequest(&subject, &ca, &duplicates, &.{}, null);
    try std.testing.expectError(
        error.DuplicateCriticalOption,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    const duplicate_extensions = [_]sshca.certificate.Extension{
        .permit_pty,
        .permit_pty,
    };
    request = makeRequest(&subject, &ca, &.{}, &duplicate_extensions, null);
    try std.testing.expectError(
        error.DuplicateExtension,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    const reserved_critical = [_]sshca.certificate.CriticalOption{
        .{ .custom = .{
            .name = "source-address",
            .value = "not-a-cidr",
        } },
    };
    request = makeRequest(&subject, &ca, &reserved_critical, &.{}, null);
    try std.testing.expectError(
        error.ReservedCriticalOptionName,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    const reserved_extension = [_]sshca.certificate.Extension{
        .{ .custom = .{
            .name = "permit-pty",
            .value = "unexpected",
        } },
    };
    request = makeRequest(&subject, &ca, &.{}, &reserved_extension, null);
    try std.testing.expectError(
        error.ReservedExtensionName,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    request = makeRequest(&subject, &ca, &.{}, &.{}, "safe\ninjected");
    try std.testing.expectError(
        error.CommentContainsLineBreak,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    request = makeRequest(&subject, &ca, &.{}, &.{}, null);
    request.key_id = "";
    try std.testing.expectError(
        error.InvalidKeyId,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    var too_many_principals = [_][]const u8{"user"} ** 257;
    request = makeRequest(&subject, &ca, &.{}, &.{}, null);
    request.principals = &too_many_principals;
    try std.testing.expectError(
        error.TooManyPrincipals,
        sshca.certificate.signCertificate(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fake.calls);
}

test "policy enforces TTL, source CIDR, RSA size, and signature length" {
    var ca = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer ca.deinit(std.testing.allocator);
    var ed25519 = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.ed25519_authorized_key,
    );
    defer ed25519.deinit(std.testing.allocator);

    var fake = FakeSigner{ .signature_len = ca.rsa.modulus.len };
    var request = makeRequest(&ed25519, &ca, &.{}, &.{}, null);
    request.validity.valid_before =
        request.validity.valid_after + sshca.policy.maximum_ttl_seconds + 61;
    try std.testing.expectError(
        error.ValidityTooLong,
        (sshca.IssuancePolicy{}).issue(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    const bad_source = [_]sshca.certificate.CriticalOption{
        .{ .source_address = "192.0.2.1/33" },
    };
    request = makeRequest(&ed25519, &ca, &bad_source, &.{}, null);
    try std.testing.expectError(
        error.InvalidSourceAddress,
        (sshca.IssuancePolicy{}).issue(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    var small_rsa = try sshca.PublicKey.initRsa(
        std.testing.allocator,
        &.{3},
        &.{ 1, 1 },
        null,
    );
    defer small_rsa.deinit(std.testing.allocator);
    request = makeRequest(&small_rsa, &ca, &.{}, &.{}, null);
    try std.testing.expectError(
        error.RsaKeyTooSmall,
        (sshca.IssuancePolicy{}).issue(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );

    fake.signature_len = ca.rsa.modulus.len - 1;
    request = makeRequest(&ed25519, &ca, &.{}, &.{}, null);
    try std.testing.expectError(
        error.InvalidSignatureLength,
        (sshca.IssuancePolicy{}).issue(
            std.testing.allocator,
            request,
            fake.digestSigner(),
        ),
    );
}

test "default interactive profile grants only permit-pty" {
    try std.testing.expectEqual(@as(usize, 1), sshca.policy.interactive_extensions.len);
    try std.testing.expectEqualStrings(
        "permit-pty",
        sshca.policy.interactive_extensions[0].name(),
    );
}

fn makeRequest(
    subject: *const sshca.PublicKey,
    ca: *const sshca.PublicKey,
    critical_options: []const sshca.certificate.CriticalOption,
    extensions: []const sshca.certificate.Extension,
    comment: ?[]const u8,
) sshca.CertificateRequest {
    return .{
        .subject_key = subject,
        .ca_key = .{
            .public_key = ca,
            .version = "test-version",
        },
        .nonce = &fixtures.nonce,
        .serial = fixtures.serial,
        .key_id = fixtures.key_id,
        .principals = &principals,
        .validity = .{
            .valid_after = fixtures.valid_after,
            .valid_before = fixtures.valid_before,
        },
        .critical_options = critical_options,
        .extensions = extensions,
        .comment = comment,
    };
}

const TestReader = struct {
    data: []const u8,
    position: usize = 0,

    fn readU32(self: *TestReader) !u32 {
        if (self.data.len - self.position < 4) return error.EndOfBuffer;
        defer self.position += 4;
        return std.mem.readInt(u32, self.data[self.position..][0..4], .big);
    }

    fn readU64(self: *TestReader) !u64 {
        if (self.data.len - self.position < 8) return error.EndOfBuffer;
        defer self.position += 8;
        return std.mem.readInt(u64, self.data[self.position..][0..8], .big);
    }

    fn readString(self: *TestReader) ![]const u8 {
        const length = try self.readU32();
        if (length > self.data.len - self.position) return error.EndOfBuffer;
        const start = self.position;
        self.position += length;
        return self.data[start..self.position];
    }

    fn expectEnd(self: TestReader) !void {
        if (self.position != self.data.len) return error.TrailingData;
    }
};
