const std = @import("std");
const sshca = @import("sshca");
const fixtures = @import("fixtures");
const openssl = @import("openssl_signer");
const test_options = @import("test_options");

test "integration scaffold exposes parity fixtures and key parser" {
    try std.testing.expect(sshca.version.len > 0);
    try std.testing.expect(fixtures.rsa_authorized_key.len > 0);
    try std.testing.expect(fixtures.ed25519_authorized_key.len > 0);

    var key = try sshca.parseAuthorizedKey(std.testing.allocator, fixtures.rsa_authorized_key);
    defer key.deinit(std.testing.allocator);
    try std.testing.expectEqual(sshca.SubjectAlgorithm.rsa, key.algorithm());
}

test "OpenSSL-signed RSA and Ed25519 certificates have exact OpenSSH metadata" {
    var ca_signer = try openssl.OpenSslSigner.init(2048);
    defer ca_signer.deinit();
    var ca_key = try ca_signer.publicKey(std.testing.allocator);
    defer ca_key.deinit(std.testing.allocator);
    const signer_probe_digest = [_]u8{42} ** 64;
    const signer_probe_signature = try ca_signer.digestSigner().signDigest(
        std.testing.allocator,
        &signer_probe_digest,
    );
    defer std.testing.allocator.free(signer_probe_signature);
    try ca_signer.verifyDigest(&signer_probe_digest, signer_probe_signature);
    var rsa_subject = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.rsa_authorized_key,
    );
    defer rsa_subject.deinit(std.testing.allocator);
    var ed25519_subject = try sshca.parseAuthorizedKey(
        std.testing.allocator,
        fixtures.ed25519_authorized_key,
    );
    defer ed25519_subject.deinit(std.testing.allocator);

    const rsa_request = makeRequest(&rsa_subject, &ca_key, &.{}, &.{}, "rsa-fixture");
    const rsa_line = try (sshca.IssuancePolicy{}).issueAndFormat(
        std.testing.allocator,
        rsa_request,
        ca_signer.digestSigner(),
    );
    defer std.testing.allocator.free(rsa_line);
    const rsa_output = try inspectCertificate(rsa_line);
    defer std.testing.allocator.free(rsa_output);
    var rsa_metadata = try CertificateMetadata.parse(std.testing.allocator, rsa_output);
    defer rsa_metadata.deinit();
    try rsa_metadata.expectEqual(.{
        .certificate_type = "ssh-rsa-cert-v01@openssh.com user certificate",
        .key_id = "testkey",
        .principals = &.{"someUser"},
    });

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
    };
    const ed25519_request = makeRequest(
        &ed25519_subject,
        &ca_key,
        &critical_options,
        &extensions,
        "ed25519-fixture",
    );
    const ed25519_line = try (sshca.IssuancePolicy{}).issueAndFormat(
        std.testing.allocator,
        ed25519_request,
        ca_signer.digestSigner(),
    );
    defer std.testing.allocator.free(ed25519_line);
    const ed25519_output = try inspectCertificate(ed25519_line);
    defer std.testing.allocator.free(ed25519_output);
    var ed25519_metadata = try CertificateMetadata.parse(
        std.testing.allocator,
        ed25519_output,
    );
    defer ed25519_metadata.deinit();
    try ed25519_metadata.expectEqual(.{
        .certificate_type = "ssh-ed25519-cert-v01@openssh.com user certificate",
        .key_id = "testkey",
        .principals = &.{"someUser"},
        .critical_options = &.{
            "force-command /usr/bin/restricted-shell",
            "source-address 192.0.2.0/24,2001:db8::/32",
        },
        .extensions = &.{
            "permit-X11-forwarding",
            "permit-agent-forwarding",
            "permit-port-forwarding",
            "permit-pty",
            "permit-user-rc",
        },
    });
}

const ExpectedMetadata = struct {
    certificate_type: []const u8,
    key_id: []const u8,
    principals: []const []const u8,
    critical_options: []const []const u8 = &.{},
    extensions: []const []const u8 = &.{},
};

const CertificateMetadata = struct {
    allocator: std.mem.Allocator,
    certificate_type: []u8,
    key_id: []u8,
    principals: [][]u8,
    critical_options: [][]u8,
    extensions: [][]u8,

    fn parse(allocator: std.mem.Allocator, output: []const u8) !CertificateMetadata {
        var certificate_type: ?[]u8 = null;
        errdefer if (certificate_type) |value| allocator.free(value);
        var key_id: ?[]u8 = null;
        errdefer if (key_id) |value| allocator.free(value);
        var principals: std.ArrayList([]u8) = .empty;
        defer principals.deinit(allocator);
        errdefer freeItems(allocator, principals.items);
        var critical_options: std.ArrayList([]u8) = .empty;
        defer critical_options.deinit(allocator);
        errdefer freeItems(allocator, critical_options.items);
        var extensions: std.ArrayList([]u8) = .empty;
        defer extensions.deinit(allocator);
        errdefer freeItems(allocator, extensions.items);

        const Section = enum {
            none,
            principals,
            critical_options,
            extensions,
        };
        var section: Section = .none;
        var lines = std.mem.splitScalar(u8, output, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "Type: ")) {
                if (certificate_type != null) return error.DuplicateCertificateType;
                certificate_type = try allocator.dupe(u8, trimmed["Type: ".len..]);
                section = .none;
            } else if (std.mem.startsWith(u8, trimmed, "Key ID: ")) {
                if (key_id != null) return error.DuplicateKeyId;
                const quoted = trimmed["Key ID: ".len..];
                if (quoted.len < 2 or quoted[0] != '"' or quoted[quoted.len - 1] != '"') {
                    return error.InvalidKeyIdOutput;
                }
                key_id = try allocator.dupe(u8, quoted[1 .. quoted.len - 1]);
                section = .none;
            } else if (std.mem.startsWith(u8, trimmed, "Principals:")) {
                section = .principals;
                try appendInlineSectionValue(
                    allocator,
                    &principals,
                    trimmed["Principals:".len..],
                );
            } else if (std.mem.startsWith(u8, trimmed, "Critical Options:")) {
                section = .critical_options;
                try appendInlineSectionValue(
                    allocator,
                    &critical_options,
                    trimmed["Critical Options:".len..],
                );
            } else if (std.mem.startsWith(u8, trimmed, "Extensions:")) {
                section = .extensions;
                try appendInlineSectionValue(
                    allocator,
                    &extensions,
                    trimmed["Extensions:".len..],
                );
            } else if (isTopLevelField(trimmed)) {
                section = .none;
            } else if (!std.mem.eql(u8, trimmed, "(none)")) {
                switch (section) {
                    .none => {},
                    .principals => try appendOwned(allocator, &principals, trimmed),
                    .critical_options => try appendOwned(
                        allocator,
                        &critical_options,
                        trimmed,
                    ),
                    .extensions => try appendOwned(allocator, &extensions, trimmed),
                }
            }
        }

        const final_certificate_type = certificate_type orelse
            return error.MissingCertificateType;
        const final_key_id = key_id orelse return error.MissingKeyId;
        const final_principals = try principals.toOwnedSlice(allocator);
        errdefer {
            freeItems(allocator, final_principals);
            allocator.free(final_principals);
        }
        const final_critical_options = try critical_options.toOwnedSlice(allocator);
        errdefer {
            freeItems(allocator, final_critical_options);
            allocator.free(final_critical_options);
        }
        const final_extensions = try extensions.toOwnedSlice(allocator);
        errdefer {
            freeItems(allocator, final_extensions);
            allocator.free(final_extensions);
        }
        return .{
            .allocator = allocator,
            .certificate_type = final_certificate_type,
            .key_id = final_key_id,
            .principals = final_principals,
            .critical_options = final_critical_options,
            .extensions = final_extensions,
        };
    }

    fn deinit(self: *CertificateMetadata) void {
        self.allocator.free(self.certificate_type);
        self.allocator.free(self.key_id);
        freeItems(self.allocator, self.principals);
        self.allocator.free(self.principals);
        freeItems(self.allocator, self.critical_options);
        self.allocator.free(self.critical_options);
        freeItems(self.allocator, self.extensions);
        self.allocator.free(self.extensions);
        self.* = undefined;
    }

    fn expectEqual(self: CertificateMetadata, expected: ExpectedMetadata) !void {
        try std.testing.expectEqualStrings(expected.certificate_type, self.certificate_type);
        try std.testing.expectEqualStrings(expected.key_id, self.key_id);
        try expectStringSlices(expected.principals, self.principals);
        try expectStringSlices(expected.critical_options, self.critical_options);
        try expectStringSlices(expected.extensions, self.extensions);
    }
};

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
            .version = "local-openssl-test",
        },
        .nonce = &fixtures.nonce,
        .serial = fixtures.serial,
        .key_id = fixtures.key_id,
        .principals = &fixtures.principals,
        .validity = .{
            .valid_after = fixtures.valid_after,
            .valid_before = fixtures.valid_before,
        },
        .critical_options = critical_options,
        .extensions = extensions,
        .comment = comment,
    };
}

fn inspectCertificate(certificate_line: []const u8) ![]u8 {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "id-cert.pub",
        .data = certificate_line,
    });
    const certificate_path = try temporary.dir.realPathFileAlloc(
        std.testing.io,
        "id-cert.pub",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(certificate_path);
    const result = try std.process.run(std.testing.allocator, std.testing.io, .{
        .argv = &.{
            test_options.ssh_keygen_path,
            "-L",
            "-f",
            certificate_path,
        },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer std.testing.allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("ssh-keygen failed: {s}\n", .{result.stderr});
                return error.SshKeygenFailed;
            }
        },
        else => return error.SshKeygenFailed,
    }
    return result.stdout;
}

fn isTopLevelField(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "Public key:") or
        std.mem.startsWith(u8, line, "Signing CA:") or
        std.mem.startsWith(u8, line, "Serial:") or
        std.mem.startsWith(u8, line, "Valid:");
}

fn appendOwned(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]u8),
    value: []const u8,
) !void {
    const owned = try allocator.dupe(u8, value);
    errdefer allocator.free(owned);
    try list.append(allocator, owned);
}

fn appendInlineSectionValue(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]u8),
    untrimmed: []const u8,
) !void {
    const value = std.mem.trim(u8, untrimmed, " \t\r");
    if (value.len == 0 or std.mem.eql(u8, value, "(none)")) return;
    try appendOwned(allocator, list, value);
}

fn freeItems(allocator: std.mem.Allocator, items: []const []u8) void {
    for (items) |item| allocator.free(item);
}

fn expectStringSlices(expected: []const []const u8, actual: []const []u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |expected_value, actual_value| {
        try std.testing.expectEqualStrings(expected_value, actual_value);
    }
}
