const std = @import("std");
const azure_core = @import("azure_core");
const keys = @import("azure_keyvault_keys");
const fixtures = @import("fixtures");
const sshca = @import("sshca");
const test_options = @import("test_options");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const vault_url = init.environ_map.get("SSHCA_TEST_VAULT_URL") orelse
        return error.MissingTestVaultUrl;
    const key_name = init.environ_map.get("SSHCA_TEST_KEY_NAME") orelse
        return error.MissingTestKeyName;
    const key_version = init.environ_map.get("SSHCA_TEST_KEY_VERSION") orelse
        return error.MissingTestKeyVersion;
    const cloud = try sshca.azure_key_vault.Cloud.parse(
        init.environ_map.get("SSHCA_TEST_CLOUD") orelse "public",
    );
    try sshca.azure_key_vault.validateVaultUrl(vault_url, cloud);

    var environment = try init.environ_map.clone(allocator);
    defer environment.deinit();
    try environment.put("AZURE_AUTHORITY_HOST", cloud.authorityHost());

    var transport = azure_core.http.StdHttpTransport.init(allocator, init.io);
    defer transport.deinit();
    var credential = try sshca.azure_credential.Credential.init(
        allocator,
        init.io,
        transport.asTransport(),
        environment,
    );
    defer credential.deinit();
    var key_client = try keys.KeyClient.init(
        allocator,
        vault_url,
        credential.asCredential(),
        transport.asTransport(),
        .{ .scope = cloud.keyVaultScope() },
    );
    defer key_client.deinit();

    var ca_key = try sshca.azure_key_vault.getCaKey(
        allocator,
        init.io,
        &key_client,
        vault_url,
        cloud,
        key_name,
        key_version,
    );
    defer ca_key.deinit();

    const ca_line = try ca_key.public_key.formatAuthorizedKey(allocator);
    var parsed_ca = try sshca.parseAuthorizedKey(allocator, ca_line);
    defer parsed_ca.deinit(allocator);
    const expected_fingerprint = try ca_key.public_key.fingerprintSha256(allocator);
    const parsed_fingerprint = try parsed_ca.fingerprintSha256(allocator);
    if (!std.mem.eql(u8, expected_fingerprint, parsed_fingerprint)) {
        return error.CaPublicKeyRoundTripMismatch;
    }

    var subject = try sshca.parseAuthorizedKey(
        allocator,
        fixtures.ed25519_authorized_key,
    );
    defer subject.deinit(allocator);
    var key_vault_signer = try sshca.azure_key_vault.AzureKeyVaultSigner.init(
        allocator,
        cloud,
        &ca_key,
        credential.asCredential(),
        transport.asTransport(),
    );
    defer key_vault_signer.deinit();
    const principals = [_][]const u8{"sshca-test"};
    var issued = try (sshca.issuer.Issuer{ .io = init.io }).issue(allocator, .{
        .subject_key = &subject,
        .ca_key = &ca_key,
        .versioned_signer = key_vault_signer.versionedSigner(),
        .key_id = "live-azure-keyvault",
        .principals = &principals,
        .requested_ttl = 3_600,
        .extensions = &sshca.policy.interactive_extensions,
        .comment = "live-azure-keyvault",
    });
    defer issued.deinit();
    try inspectCertificate(allocator, init.io, issued.authorized_key);

    std.debug.print(
        "live Azure validation succeeded for {s} version {s}\n",
        .{ ca_key.key_id, ca_key.version },
    );
}

fn inspectCertificate(
    allocator: std.mem.Allocator,
    io: std.Io,
    certificate_line: []const u8,
) !void {
    var random: [8]u8 = undefined;
    try io.randomSecure(&random);
    const suffix = std.fmt.bytesToHex(random, .lower);
    const temporary_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/live-azure-{s}",
        .{suffix},
    );
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, temporary_path);
    defer cwd.deleteTree(io, temporary_path) catch {};
    var temporary = try cwd.openDir(io, temporary_path, .{});
    defer temporary.close(io);
    try temporary.writeFile(io, .{
        .sub_path = "live-cert.pub",
        .data = certificate_line,
    });
    const result = try std.process.run(allocator, io, .{
        .argv = &.{
            test_options.ssh_keygen_path,
            "-L",
            "-f",
            "live-cert.pub",
        },
        .cwd = .{ .dir = temporary },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.SshKeygenFailed,
        else => return error.SshKeygenFailed,
    }
    if (std.mem.indexOf(
        u8,
        result.stdout,
        "Type: ssh-ed25519-cert-v01@openssh.com user certificate",
    ) == null) return error.UnexpectedCertificateType;
    if (std.mem.indexOf(u8, result.stdout, "Key ID: \"live-azure-keyvault\"") == null) {
        return error.UnexpectedCertificateKeyId;
    }
    if (std.mem.indexOf(u8, result.stdout, "sshca-test") == null) {
        return error.UnexpectedCertificatePrincipal;
    }
}
