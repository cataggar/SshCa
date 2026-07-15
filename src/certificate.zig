const std = @import("std");
const public_key = @import("public_key.zig");
const signer = @import("signer.zig");
const wire = @import("wire.zig");

pub const rsa_certificate_algorithm = "rsa-sha2-512-cert-v01@openssh.com";
pub const ed25519_certificate_algorithm = "ssh-ed25519-cert-v01@openssh.com";
pub const signature_algorithm = "rsa-sha2-512";
pub const user_certificate_type: u32 = 1;
pub const max_principals: usize = 256;

pub const VersionedCaPublicKey = struct {
    public_key: *const public_key.PublicKey,
    version: []const u8,
};

pub const Validity = struct {
    valid_after: u64,
    valid_before: u64,
};

pub const NamedData = struct {
    name: []const u8,
    value: []const u8,
};

pub const CriticalOption = union(enum) {
    force_command: []const u8,
    source_address: []const u8,
    custom: NamedData,

    pub fn name(self: CriticalOption) []const u8 {
        return switch (self) {
            .force_command => "force-command",
            .source_address => "source-address",
            .custom => |custom| custom.name,
        };
    }
};

pub const Extension = union(enum) {
    permit_agent_forwarding,
    permit_port_forwarding,
    permit_pty,
    permit_user_rc,
    permit_x11_forwarding,
    custom: NamedData,

    pub fn name(self: Extension) []const u8 {
        return switch (self) {
            .permit_agent_forwarding => "permit-agent-forwarding",
            .permit_port_forwarding => "permit-port-forwarding",
            .permit_pty => "permit-pty",
            .permit_user_rc => "permit-user-rc",
            .permit_x11_forwarding => "permit-X11-forwarding",
            .custom => |custom| custom.name,
        };
    }
};

pub const CertificateRequest = struct {
    subject_key: *const public_key.PublicKey,
    ca_key: VersionedCaPublicKey,
    nonce: []const u8,
    serial: u64,
    key_id: []const u8,
    principals: []const []const u8,
    validity: Validity,
    critical_options: []const CriticalOption = &.{},
    extensions: []const Extension = &.{},
    comment: ?[]const u8 = null,
};

pub fn certificateAlgorithm(subject_key: public_key.PublicKey) []const u8 {
    return switch (subject_key) {
        .rsa => rsa_certificate_algorithm,
        .ed25519 => ed25519_certificate_algorithm,
    };
}

pub fn validateRequest(request: CertificateRequest) !void {
    if (request.nonce.len != 32) return error.InvalidNonceLength;
    try validateText(request.ca_key.version, false, error.InvalidCaKeyVersion);
    switch (request.ca_key.public_key.*) {
        .rsa => {},
        .ed25519 => return error.UnsupportedCaKeyAlgorithm,
    }

    try validateText(request.key_id, false, error.InvalidKeyId);
    if (request.principals.len == 0) return error.MissingPrincipals;
    if (request.principals.len > max_principals) return error.TooManyPrincipals;
    for (request.principals) |principal| {
        try validateText(principal, false, error.InvalidPrincipal);
    }
    if (request.validity.valid_before <= request.validity.valid_after) {
        return error.InvalidValidity;
    }

    for (request.critical_options, 0..) |option, index| {
        try validateCriticalOption(option);
        for (request.critical_options[0..index]) |previous| {
            if (std.mem.eql(u8, option.name(), previous.name())) {
                return error.DuplicateCriticalOption;
            }
        }
    }
    for (request.extensions, 0..) |extension, index| {
        try validateExtension(extension);
        for (request.extensions[0..index]) |previous| {
            if (std.mem.eql(u8, extension.name(), previous.name())) {
                return error.DuplicateExtension;
            }
        }
    }
    if (request.comment) |comment| try validateComment(comment);
}

pub fn buildToBeSigned(
    allocator: std.mem.Allocator,
    request: CertificateRequest,
) ![]u8 {
    try validateRequest(request);

    var writer = wire.Writer.init(allocator);
    defer writer.deinit();
    try writer.writeString(certificateAlgorithm(request.subject_key.*));
    try writer.writeString(request.nonce);
    try writePublicKeyComponents(&writer, request.subject_key.*);
    try writer.writeU64(request.serial);
    try writer.writeU32(user_certificate_type);
    try writer.writeString(request.key_id);
    try writePrincipals(allocator, &writer, request.principals);
    try writer.writeU64(request.validity.valid_after);
    try writer.writeU64(request.validity.valid_before);
    try writeCriticalOptions(allocator, &writer, request.critical_options);
    try writeExtensions(allocator, &writer, request.extensions);
    try writer.writeString("");

    const ca_blob = try request.ca_key.public_key.authorizedKeyBlob(allocator);
    defer allocator.free(ca_blob);
    try writer.writeString(ca_blob);
    return writer.toOwnedSlice();
}

pub fn signCertificate(
    allocator: std.mem.Allocator,
    request: CertificateRequest,
    digest_signer: signer.DigestSigner,
) ![]u8 {
    const to_be_signed = try buildToBeSigned(allocator, request);
    defer allocator.free(to_be_signed);

    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(to_be_signed, &digest, .{});
    const signature = try digest_signer.signDigest(allocator, &digest);
    defer allocator.free(signature);

    const expected_signature_len = switch (request.ca_key.public_key.*) {
        .rsa => |rsa| rsa.modulus.len,
        .ed25519 => return error.UnsupportedCaKeyAlgorithm,
    };
    if (signature.len != expected_signature_len) return error.InvalidSignatureLength;

    var signature_blob = wire.Writer.init(allocator);
    defer signature_blob.deinit();
    try signature_blob.writeString(signature_algorithm);
    try signature_blob.writeString(signature);

    var certificate = wire.Writer.init(allocator);
    defer certificate.deinit();
    try certificate.writeRaw(to_be_signed);
    try certificate.writeString(signature_blob.items());
    return certificate.toOwnedSlice();
}

pub fn signAndFormatCertificate(
    allocator: std.mem.Allocator,
    request: CertificateRequest,
    digest_signer: signer.DigestSigner,
) ![]u8 {
    try validateRequest(request);
    const certificate = try signCertificate(allocator, request, digest_signer);
    defer allocator.free(certificate);
    return formatCertificate(allocator, request.subject_key.*, certificate, request.comment);
}

pub fn formatCertificate(
    allocator: std.mem.Allocator,
    subject_key: public_key.PublicKey,
    certificate: []const u8,
    comment: ?[]const u8,
) ![]u8 {
    const normalized_comment = if (comment) |value| blk: {
        try validateComment(value);
        const trimmed = std.mem.trim(u8, value, " \t");
        break :blk if (trimmed.len == 0) null else trimmed;
    } else null;

    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(certificate.len));
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, certificate);

    if (normalized_comment) |value| {
        return std.fmt.allocPrint(
            allocator,
            "{s} {s} {s}",
            .{ certificateAlgorithm(subject_key), encoded, value },
        );
    }
    return std.fmt.allocPrint(
        allocator,
        "{s} {s}",
        .{ certificateAlgorithm(subject_key), encoded },
    );
}

fn writePublicKeyComponents(
    writer: *wire.Writer,
    key: public_key.PublicKey,
) !void {
    switch (key) {
        .rsa => |rsa| {
            try writer.writePositiveMpint(rsa.exponent);
            try writer.writePositiveMpint(rsa.modulus);
        },
        .ed25519 => |ed25519| try writer.writeString(&ed25519.key),
    }
}

fn writePrincipals(
    allocator: std.mem.Allocator,
    writer: *wire.Writer,
    principals: []const []const u8,
) !void {
    var nested = wire.Writer.init(allocator);
    defer nested.deinit();
    for (principals) |principal| try nested.writeString(principal);
    try writer.writeNested(nested);
}

fn writeCriticalOptions(
    allocator: std.mem.Allocator,
    writer: *wire.Writer,
    options: []const CriticalOption,
) !void {
    const sorted = try allocator.dupe(CriticalOption, options);
    defer allocator.free(sorted);
    std.mem.sort(CriticalOption, sorted, {}, criticalOptionLessThan);

    var nested = wire.Writer.init(allocator);
    defer nested.deinit();
    for (sorted) |option| {
        try nested.writeString(option.name());
        switch (option) {
            .force_command, .source_address => |value| {
                var encoded_value = wire.Writer.init(allocator);
                defer encoded_value.deinit();
                try encoded_value.writeString(value);
                try nested.writeNested(encoded_value);
            },
            .custom => |custom| try nested.writeString(custom.value),
        }
    }
    try writer.writeNested(nested);
}

fn writeExtensions(
    allocator: std.mem.Allocator,
    writer: *wire.Writer,
    extensions: []const Extension,
) !void {
    const sorted = try allocator.dupe(Extension, extensions);
    defer allocator.free(sorted);
    std.mem.sort(Extension, sorted, {}, extensionLessThan);

    var nested = wire.Writer.init(allocator);
    defer nested.deinit();
    for (sorted) |extension| {
        try nested.writeString(extension.name());
        switch (extension) {
            .custom => |custom| try nested.writeString(custom.value),
            else => try nested.writeString(""),
        }
    }
    try writer.writeNested(nested);
}

fn criticalOptionLessThan(_: void, left: CriticalOption, right: CriticalOption) bool {
    return std.mem.order(u8, left.name(), right.name()) == .lt;
}

fn extensionLessThan(_: void, left: Extension, right: Extension) bool {
    return std.mem.order(u8, left.name(), right.name()) == .lt;
}

fn validateCriticalOption(option: CriticalOption) !void {
    try validateText(option.name(), false, error.InvalidCriticalOptionName);
    switch (option) {
        .force_command => |value| {
            try validateText(value, false, error.InvalidForceCommand);
        },
        .source_address => |value| {
            try validateText(value, false, error.InvalidSourceAddress);
        },
        .custom => |custom| {
            if (std.mem.eql(u8, custom.name, "force-command") or
                std.mem.eql(u8, custom.name, "source-address"))
            {
                return error.ReservedCriticalOptionName;
            }
        },
    }
}

fn validateExtension(extension: Extension) !void {
    try validateText(extension.name(), false, error.InvalidExtensionName);
    if (extension == .custom) {
        const name = extension.custom.name;
        if (std.mem.eql(u8, name, "permit-agent-forwarding") or
            std.mem.eql(u8, name, "permit-port-forwarding") or
            std.mem.eql(u8, name, "permit-pty") or
            std.mem.eql(u8, name, "permit-user-rc") or
            std.mem.eql(u8, name, "permit-X11-forwarding"))
        {
            return error.ReservedExtensionName;
        }
    }
}

fn validateComment(comment: []const u8) !void {
    if (std.mem.indexOfScalar(u8, comment, 0) != null) return error.NullByte;
    if (std.mem.indexOfAny(u8, comment, "\r\n") != null) {
        return error.CommentContainsLineBreak;
    }
}

fn validateText(value: []const u8, allow_empty: bool, empty_error: anyerror) !void {
    if (!allow_empty and value.len == 0) return empty_error;
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.NullByte;
}

test "certificate algorithm follows the subject key type" {
    var rsa = try public_key.PublicKey.initRsa(
        std.testing.allocator,
        &.{3},
        &.{5},
        null,
    );
    defer rsa.deinit(std.testing.allocator);
    var ed25519 = try public_key.PublicKey.initEd25519(
        std.testing.allocator,
        &([_]u8{1} ** 32),
        null,
    );
    defer ed25519.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(rsa_certificate_algorithm, certificateAlgorithm(rsa));
    try std.testing.expectEqualStrings(
        ed25519_certificate_algorithm,
        certificateAlgorithm(ed25519),
    );
}
