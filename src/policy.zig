const std = @import("std");
const certificate = @import("certificate.zig");
const signer = @import("signer.zig");

pub const default_ttl_seconds: u64 = 60 * 60;
pub const maximum_ttl_seconds: u64 = 8 * 60 * 60;
pub const default_not_before_skew_seconds: u64 = 60;
pub const default_minimum_rsa_bits: usize = 2048;

pub const interactive_extensions = [_]certificate.Extension{
    .permit_pty,
};

pub const IssuancePolicy = struct {
    default_ttl: u64 = default_ttl_seconds,
    maximum_ttl: u64 = maximum_ttl_seconds,
    not_before_skew: u64 = default_not_before_skew_seconds,
    minimum_rsa_bits: usize = default_minimum_rsa_bits,

    pub fn validity(
        self: IssuancePolicy,
        now: u64,
        requested_ttl: ?u64,
    ) !certificate.Validity {
        try self.validateConfiguration();
        const ttl = requested_ttl orelse self.default_ttl;
        if (ttl == 0) return error.InvalidTtl;
        if (ttl > self.maximum_ttl) return error.ValidityTooLong;
        if (ttl > std.math.maxInt(u64) - now) return error.ValidityOverflow;
        return .{
            .valid_after = now -| self.not_before_skew,
            .valid_before = now + ttl,
        };
    }

    pub fn validate(
        self: IssuancePolicy,
        request: certificate.CertificateRequest,
    ) !void {
        try self.validateConfiguration();
        try certificate.validateRequest(request);

        const validity_window =
            request.validity.valid_before - request.validity.valid_after;
        if (self.not_before_skew > std.math.maxInt(u64) - self.maximum_ttl) {
            return error.InvalidPolicy;
        }
        if (validity_window > self.maximum_ttl + self.not_before_skew) {
            return error.ValidityTooLong;
        }
        switch (request.subject_key.*) {
            .rsa => try request.subject_key.validateRsaMinimumBits(self.minimum_rsa_bits),
            .ed25519 => {},
        }
        for (request.critical_options) |option| {
            switch (option) {
                .source_address => |value| try validateSourceAddresses(value),
                else => {},
            }
        }
    }

    pub fn issue(
        self: IssuancePolicy,
        allocator: std.mem.Allocator,
        request: certificate.CertificateRequest,
        digest_signer: signer.DigestSigner,
    ) ![]u8 {
        try self.validate(request);
        return certificate.signCertificate(allocator, request, digest_signer);
    }

    pub fn issueAndFormat(
        self: IssuancePolicy,
        allocator: std.mem.Allocator,
        request: certificate.CertificateRequest,
        digest_signer: signer.DigestSigner,
    ) ![]u8 {
        try self.validate(request);
        return certificate.signAndFormatCertificate(allocator, request, digest_signer);
    }

    fn validateConfiguration(self: IssuancePolicy) !void {
        if (self.default_ttl == 0 or self.default_ttl > self.maximum_ttl) {
            return error.InvalidPolicy;
        }
        if (self.maximum_ttl == 0 or self.minimum_rsa_bits == 0) {
            return error.InvalidPolicy;
        }
    }
};

pub fn validateSourceAddresses(value: []const u8) !void {
    var entries = std.mem.splitScalar(u8, value, ',');
    var count: usize = 0;
    while (entries.next()) |entry_untrimmed| {
        const entry = std.mem.trim(u8, entry_untrimmed, " \t");
        if (entry.len == 0) return error.InvalidSourceAddress;
        if (entry.len != entry_untrimmed.len) return error.InvalidSourceAddress;
        const slash = std.mem.lastIndexOfScalar(u8, entry, '/') orelse
            return error.InvalidSourceAddress;
        if (slash == 0 or slash == entry.len - 1) return error.InvalidSourceAddress;
        const address = entry[0..slash];
        const prefix_text = entry[slash + 1 ..];
        if (std.mem.indexOfScalar(u8, address, '%') != null) {
            return error.InvalidSourceAddress;
        }
        for (prefix_text) |byte| {
            if (byte < '0' or byte > '9') return error.InvalidSourceAddress;
        }
        const prefix = std.fmt.parseInt(u8, prefix_text, 10) catch
            return error.InvalidSourceAddress;
        if (std.mem.indexOfScalar(u8, address, ':') != null) {
            const parsed = std.Io.net.Ip6Address.parse(address, 0) catch
                return error.InvalidSourceAddress;
            if (prefix > 128) return error.InvalidSourceAddress;
            if (hasNonZeroHostBits(&parsed.bytes, prefix)) {
                return error.InvalidSourceAddress;
            }
        } else {
            const parsed = std.Io.net.Ip4Address.parse(address, 0) catch
                return error.InvalidSourceAddress;
            if (prefix > 32) return error.InvalidSourceAddress;
            if (hasNonZeroHostBits(&parsed.bytes, prefix)) {
                return error.InvalidSourceAddress;
            }
        }
        count += 1;
    }
    if (count == 0) return error.InvalidSourceAddress;
}

fn hasNonZeroHostBits(address: []const u8, prefix: u8) bool {
    const full_bytes = prefix / 8;
    const partial_bits = prefix % 8;
    var host_start: usize = full_bytes;
    if (partial_bits != 0) {
        const host_mask: u8 = @as(u8, 0xff) >> @intCast(partial_bits);
        if (address[full_bytes] & host_mask != 0) return true;
        host_start += 1;
    }
    for (address[host_start..]) |byte| {
        if (byte != 0) return true;
    }
    return false;
}

test "default validity includes clock skew and one hour TTL" {
    const validity_value = try (IssuancePolicy{}).validity(1_000, null);
    try std.testing.expectEqual(@as(u64, 940), validity_value.valid_after);
    try std.testing.expectEqual(@as(u64, 4_600), validity_value.valid_before);
}

test "source address validation accepts IPv4 and IPv6 CIDR values" {
    try validateSourceAddresses("192.0.2.0/24,2001:db8::/32");
    try std.testing.expectError(
        error.InvalidSourceAddress,
        validateSourceAddresses("192.0.2.1/33"),
    );
    try std.testing.expectError(
        error.InvalidSourceAddress,
        validateSourceAddresses("2001:db8::1"),
    );
    try std.testing.expectError(
        error.InvalidSourceAddress,
        validateSourceAddresses("192.0.2.1/24"),
    );
    try std.testing.expectError(
        error.InvalidSourceAddress,
        validateSourceAddresses("2001:db8::1/32"),
    );
}
