const std = @import("std");
const sshca = @import("sshca");
const openssl = @import("openssl_signer");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 5) return error.InvalidArguments;

    const output_path = args[1];
    const rsa_key_path = args[2];
    const ed25519_key_path = args[3];
    const now = try std.fmt.parseInt(u64, args[4], 10);
    var output_dir = try std.Io.Dir.cwd().openDir(init.io, output_path, .{});
    defer output_dir.close(init.io);

    var rsa_subject = try readPublicKey(allocator, init.io, rsa_key_path);
    defer rsa_subject.deinit(allocator);
    var ed25519_subject = try readPublicKey(allocator, init.io, ed25519_key_path);
    defer ed25519_subject.deinit(allocator);

    var ca_signer = try openssl.OpenSslSigner.init(2048);
    defer ca_signer.deinit();
    var ca_key = try ca_signer.publicKey(allocator);
    defer ca_key.deinit(allocator);
    const ca_line = try ca_key.formatAuthorizedKey(allocator);
    try writeLine(output_dir, init.io, "trusted-user-ca-keys", ca_line);

    if (now < 3_600) return error.InvalidSystemTime;
    const valid = sshca.certificate.Validity{
        .valid_after = now - 60,
        .valid_before = now + 3_600,
    };
    const expired = sshca.certificate.Validity{
        .valid_after = now - 3_600,
        .valid_before = now - 60,
    };

    try issue(
        allocator,
        output_dir,
        init.io,
        &rsa_subject,
        &ca_key,
        ca_signer.digestSigner(),
        "rsa-valid-cert.pub",
        "sshca-test",
        valid,
        1,
    );
    try issue(
        allocator,
        output_dir,
        init.io,
        &ed25519_subject,
        &ca_key,
        ca_signer.digestSigner(),
        "ed25519-valid-cert.pub",
        "sshca-test",
        valid,
        2,
    );
    try issue(
        allocator,
        output_dir,
        init.io,
        &ed25519_subject,
        &ca_key,
        ca_signer.digestSigner(),
        "ed25519-wrong-principal-cert.pub",
        "not-sshca-test",
        valid,
        3,
    );
    try issue(
        allocator,
        output_dir,
        init.io,
        &ed25519_subject,
        &ca_key,
        ca_signer.digestSigner(),
        "ed25519-expired-cert.pub",
        "sshca-test",
        expired,
        4,
    );
}

fn readPublicKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !sshca.PublicKey {
    const contents = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(sshca.public_key.max_authorized_key_len),
    );
    return sshca.parseAuthorizedKey(allocator, contents);
}

fn issue(
    allocator: std.mem.Allocator,
    output_dir: std.Io.Dir,
    io: std.Io,
    subject: *const sshca.PublicKey,
    ca_key: *const sshca.PublicKey,
    digest_signer: sshca.DigestSigner,
    output_name: []const u8,
    principal: []const u8,
    validity: sshca.certificate.Validity,
    serial: u64,
) !void {
    const nonce = [_]u8{0x5a} ** 32;
    const principals = [_][]const u8{principal};
    const line = try (sshca.IssuancePolicy{}).issueAndFormat(
        allocator,
        .{
            .subject_key = subject,
            .ca_key = .{
                .public_key = ca_key,
                .version = "sshd-integration",
            },
            .nonce = &nonce,
            .serial = serial,
            .key_id = "sshd-integration",
            .principals = &principals,
            .validity = validity,
            .comment = output_name,
        },
        digest_signer,
    );
    try writeLine(output_dir, io, output_name, line);
}

fn writeLine(
    output_dir: std.Io.Dir,
    io: std.Io,
    name: []const u8,
    line: []const u8,
) !void {
    var file = try output_dir.createFile(io, name, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, line);
    try file.writeStreamingAll(io, "\n");
}
