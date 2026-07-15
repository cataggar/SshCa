const std = @import("std");
const azure_key_vault = @import("azure_key_vault.zig");
const certificate = @import("certificate.zig");
const policy = @import("policy.zig");
const public_key = @import("public_key.zig");
const signer = @import("signer.zig");

pub const IssueRequest = struct {
    subject_key: *const public_key.PublicKey,
    ca_key: *const azure_key_vault.CaKey,
    versioned_signer: signer.VersionedDigestSigner,
    key_id: []const u8,
    principals: []const []const u8,
    requested_ttl: ?u64 = null,
    critical_options: []const certificate.CriticalOption = &.{},
    extensions: []const certificate.Extension = &.{},
    comment: ?[]const u8 = null,
};

pub const TestOverrides = struct {
    now: ?u64 = null,
    nonce: ?[32]u8 = null,
    serial: ?u64 = null,
};

pub const AuditMetadata = struct {
    allocator: std.mem.Allocator,
    ca_key_id: []u8,
    ca_key_version: []u8,
    subject_fingerprint: []u8,
    key_id: []u8,
    principals: [][]u8,
    serial: u64,
    valid_after: u64,
    valid_before: u64,

    pub fn deinit(self: *AuditMetadata) void {
        for (self.principals) |principal| self.allocator.free(principal);
        self.allocator.free(self.principals);
        self.allocator.free(self.ca_key_id);
        self.allocator.free(self.ca_key_version);
        self.allocator.free(self.subject_fingerprint);
        self.allocator.free(self.key_id);
        self.* = undefined;
    }
};

pub const IssuedCertificate = struct {
    allocator: std.mem.Allocator,
    authorized_key: []u8,
    audit: AuditMetadata,

    pub fn deinit(self: *IssuedCertificate) void {
        self.allocator.free(self.authorized_key);
        self.audit.deinit();
        self.* = undefined;
    }
};

pub const Issuer = struct {
    io: std.Io,
    issuance_policy: policy.IssuancePolicy = .{},

    pub fn issue(
        self: Issuer,
        allocator: std.mem.Allocator,
        request: IssueRequest,
    ) !IssuedCertificate {
        return self.issueWithOverrides(allocator, request, .{});
    }

    pub fn issueWithOverrides(
        self: Issuer,
        allocator: std.mem.Allocator,
        request: IssueRequest,
        overrides: TestOverrides,
    ) !IssuedCertificate {
        if (!std.mem.eql(u8, request.versioned_signer.key_id, request.ca_key.key_id)) {
            return error.CaSignerVersionMismatch;
        }

        const nonce = overrides.nonce orelse nonce: {
            var generated: [32]u8 = undefined;
            try self.io.randomSecure(&generated);
            break :nonce generated;
        };
        const serial = if (overrides.serial) |value|
            value
        else
            try randomNonZeroSerial(self.io);
        if (serial == 0) return error.InvalidSerial;

        const now = if (overrides.now) |value| value else now: {
            const timestamp = std.Io.Timestamp.now(self.io, .real).toSeconds();
            if (timestamp < 0) return error.InvalidSystemTime;
            break :now @as(u64, @intCast(timestamp));
        };
        const validity = try self.issuance_policy.validity(now, request.requested_ttl);
        const cert_request = certificate.CertificateRequest{
            .subject_key = request.subject_key,
            .ca_key = .{
                .public_key = &request.ca_key.public_key,
                .version = request.ca_key.version,
            },
            .nonce = &nonce,
            .serial = serial,
            .key_id = request.key_id,
            .principals = request.principals,
            .validity = validity,
            .critical_options = request.critical_options,
            .extensions = request.extensions,
            .comment = request.comment,
        };
        const authorized_key = try self.issuance_policy.issueAndFormat(
            allocator,
            cert_request,
            request.versioned_signer.digest_signer,
        );
        errdefer allocator.free(authorized_key);

        var audit = try createAuditMetadata(
            allocator,
            request,
            serial,
            validity,
        );
        errdefer audit.deinit();
        return .{
            .allocator = allocator,
            .authorized_key = authorized_key,
            .audit = audit,
        };
    }
};

fn randomNonZeroSerial(io: std.Io) !u64 {
    while (true) {
        var bytes: [8]u8 = undefined;
        try io.randomSecure(&bytes);
        const serial = std.mem.readInt(u64, &bytes, .big);
        if (serial != 0) return serial;
    }
}

fn createAuditMetadata(
    allocator: std.mem.Allocator,
    request: IssueRequest,
    serial: u64,
    validity: certificate.Validity,
) !AuditMetadata {
    const ca_key_id = try allocator.dupe(u8, request.ca_key.key_id);
    errdefer allocator.free(ca_key_id);
    const ca_key_version = try allocator.dupe(u8, request.ca_key.version);
    errdefer allocator.free(ca_key_version);
    const subject_fingerprint = try request.subject_key.fingerprintSha256(allocator);
    errdefer allocator.free(subject_fingerprint);
    const key_id = try allocator.dupe(u8, request.key_id);
    errdefer allocator.free(key_id);

    const principals = try allocator.alloc([]u8, request.principals.len);
    errdefer allocator.free(principals);
    var initialized: usize = 0;
    errdefer for (principals[0..initialized]) |principal| allocator.free(principal);
    for (request.principals, 0..) |principal, index| {
        principals[index] = try allocator.dupe(u8, principal);
        initialized += 1;
    }

    return .{
        .allocator = allocator,
        .ca_key_id = ca_key_id,
        .ca_key_version = ca_key_version,
        .subject_fingerprint = subject_fingerprint,
        .key_id = key_id,
        .principals = principals,
        .serial = serial,
        .valid_after = validity.valid_after,
        .valid_before = validity.valid_before,
    };
}

test "issuer binds signer and public key to the same Key Vault version" {
    const allocator = std.testing.allocator;
    const exponent = [_]u8{3};
    const modulus = [_]u8{0x81};
    const ca_public_key = try public_key.PublicKey.initRsa(
        allocator,
        &exponent,
        &modulus,
        "",
    );
    var ca_key = azure_key_vault.CaKey{
        .allocator = allocator,
        .vault_url = try allocator.dupe(u8, "https://vm17kv.vault.azure.net"),
        .key_id = try allocator.dupe(u8, "https://vm17kv.vault.azure.net/keys/ssh-ca/v1"),
        .name = try allocator.dupe(u8, "ssh-ca"),
        .version = try allocator.dupe(u8, "v1"),
        .public_key = ca_public_key,
    };
    defer ca_key.deinit();

    const subject_bytes = [_]u8{0x42} ** 32;
    var subject = try public_key.PublicKey.initEd25519(
        allocator,
        &subject_bytes,
        "test",
    );
    defer subject.deinit(allocator);

    const TestSigner = struct {
        fn sign(
            _: *anyopaque,
            signature_allocator: std.mem.Allocator,
            _: *const [64]u8,
        ) anyerror![]u8 {
            return signature_allocator.dupe(u8, &.{0x01});
        }
    };
    var context: u8 = 0;
    const digest_signer = signer.DigestSigner.init(&context, TestSigner.sign);
    const principals = [_][]const u8{"alice"};
    const request = IssueRequest{
        .subject_key = &subject,
        .ca_key = &ca_key,
        .versioned_signer = signer.VersionedDigestSigner.init(ca_key.key_id, digest_signer),
        .key_id = "alice@example",
        .principals = &principals,
    };

    var issued = try (Issuer{
        .io = std.testing.io,
        .issuance_policy = .{ .minimum_rsa_bits = 1 },
    }).issueWithOverrides(
        allocator,
        request,
        .{
            .now = 1_000,
            .nonce = [_]u8{0x23} ** 32,
            .serial = 42,
        },
    );
    defer issued.deinit();

    try std.testing.expectEqual(@as(u64, 42), issued.audit.serial);
    try std.testing.expectEqualStrings("v1", issued.audit.ca_key_version);
    try std.testing.expect(std.mem.startsWith(
        u8,
        issued.authorized_key,
        "ssh-ed25519-cert-v01@openssh.com ",
    ));

    var mismatched = request;
    mismatched.versioned_signer = signer.VersionedDigestSigner.init(
        "https://vm17kv.vault.azure.net/keys/ssh-ca/v2",
        digest_signer,
    );
    try std.testing.expectError(
        error.CaSignerVersionMismatch,
        (Issuer{
            .io = std.testing.io,
            .issuance_policy = .{ .minimum_rsa_bits = 1 },
        }).issueWithOverrides(
            allocator,
            mismatched,
            .{
                .now = 1_000,
                .nonce = [_]u8{0x23} ** 32,
                .serial = 42,
            },
        ),
    );
}
