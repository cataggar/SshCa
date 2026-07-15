const std = @import("std");

pub const DigestSigner = struct {
    context: *anyopaque,
    sign_fn: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        digest: *const [64]u8,
    ) anyerror![]u8,

    pub fn init(
        context: *anyopaque,
        sign_fn: *const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            digest: *const [64]u8,
        ) anyerror![]u8,
    ) DigestSigner {
        return .{
            .context = context,
            .sign_fn = sign_fn,
        };
    }

    pub fn signDigest(
        self: DigestSigner,
        allocator: std.mem.Allocator,
        digest: *const [64]u8,
    ) ![]u8 {
        return self.sign_fn(self.context, allocator, digest);
    }
};

pub const VersionedDigestSigner = struct {
    key_id: []const u8,
    digest_signer: DigestSigner,

    pub fn init(key_id: []const u8, digest_signer: DigestSigner) VersionedDigestSigner {
        return .{
            .key_id = key_id,
            .digest_signer = digest_signer,
        };
    }

    pub fn signDigest(
        self: VersionedDigestSigner,
        allocator: std.mem.Allocator,
        digest: *const [64]u8,
    ) ![]u8 {
        return self.digest_signer.signDigest(allocator, digest);
    }
};

test "digest signer forwards the exact SHA-512 digest" {
    const Recorder = struct {
        called: bool = false,
        digest: [64]u8 = undefined,

        fn sign(
            context: *anyopaque,
            allocator: std.mem.Allocator,
            digest: *const [64]u8,
        ) ![]u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.called = true;
            self.digest = digest.*;
            return allocator.dupe(u8, &.{1});
        }
    };

    var recorder = Recorder{};
    const signer = DigestSigner.init(&recorder, Recorder.sign);
    const digest = [_]u8{42} ** 64;
    const signature = try signer.signDigest(std.testing.allocator, &digest);
    defer std.testing.allocator.free(signature);

    try std.testing.expect(recorder.called);
    try std.testing.expectEqualSlices(u8, &digest, &recorder.digest);
}
