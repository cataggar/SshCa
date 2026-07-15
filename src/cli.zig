const std = @import("std");
const azure_core = @import("azure_core");
const keys = @import("azure_keyvault_keys");
const azure_credential = @import("azure_credential.zig");
const azure_key_vault = @import("azure_key_vault.zig");
const certificate = @import("certificate.zig");
const issuer = @import("issuer.zig");
const policy = @import("policy.zig");
const public_key = @import("public_key.zig");

const package_version = "0.1.0";

pub const ExitCode = enum(u8) {
    success = 0,
    failure = 1,
    usage = 2,
};

pub fn run(
    init: std.process.Init,
    args: []const []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !ExitCode {
    if (args.len <= 1 or isHelp(args[1])) {
        try writeHelp(stdout);
        return .success;
    }
    if (std.mem.eql(u8, args[1], "--version")) {
        try stdout.print("sshca {s}\n", .{package_version});
        return .success;
    }

    const allocator = init.arena.allocator();
    if (std.mem.eql(u8, args[1], "sign")) {
        const options = parseSignOptions(allocator, args[2..]) catch |err| {
            try stderr.print("sshca sign: {s}\n", .{@errorName(err)});
            return .usage;
        };
        return executeSign(init, options, stdout);
    }
    if (std.mem.eql(u8, args[1], "ca")) {
        if (args.len < 3) {
            try stderr.writeAll("sshca: missing ca subcommand\n");
            return .usage;
        }
        if (std.mem.eql(u8, args[2], "ensure")) {
            const options = parseCaOptions(args[3..], .provisioning) catch |err| {
                try stderr.print("sshca ca ensure: {s}\n", .{@errorName(err)});
                return .usage;
            };
            return executeEnsure(init, options, stdout);
        }
        if (std.mem.eql(u8, args[2], "rotate")) {
            const options = parseCaOptions(args[3..], .provisioning) catch |err| {
                try stderr.print("sshca ca rotate: {s}\n", .{@errorName(err)});
                return .usage;
            };
            return executeRotate(init, options, stdout);
        }
        if (std.mem.eql(u8, args[2], "public-key")) {
            const options = parseCaOptions(args[3..], .public_key) catch |err| {
                try stderr.print("sshca ca public-key: {s}\n", .{@errorName(err)});
                return .usage;
            };
            return executePublicKey(init, options, stdout);
        }
        try stderr.print("sshca: unknown ca subcommand '{s}'\n", .{args[2]});
        return .usage;
    }

    try stderr.print("sshca: unknown command '{s}'\n", .{args[1]});
    return .usage;
}

const CaOptions = struct {
    vault_url: []const u8,
    key_name: []const u8,
    cloud: azure_key_vault.Cloud = .public,
    bits: u16 = 3072,
    hsm: bool = false,
    version: ?[]const u8 = null,
    cert_authority: bool = false,
};

const CaCommandMode = enum {
    provisioning,
    public_key,
};

fn parseCaOptions(args: []const []const u8, mode: CaCommandMode) !CaOptions {
    var options = CaOptions{
        .vault_url = "",
        .key_name = "",
    };
    var parser = ArgParser.init(args);
    while (parser.next()) |arg| {
        if (std.mem.eql(u8, arg, "--vault-url")) {
            options.vault_url = try parser.value();
        } else if (std.mem.eql(u8, arg, "--name") or
            std.mem.eql(u8, arg, "--key-name"))
        {
            options.key_name = try parser.value();
        } else if (std.mem.eql(u8, arg, "--cloud")) {
            options.cloud = try azure_key_vault.Cloud.parse(try parser.value());
        } else if (mode == .provisioning and std.mem.eql(u8, arg, "--bits")) {
            options.bits = std.fmt.parseInt(u16, try parser.value(), 10) catch
                return error.InvalidCaKeySize;
        } else if (mode == .provisioning and std.mem.eql(u8, arg, "--hsm")) {
            options.hsm = true;
        } else if (mode == .public_key and std.mem.eql(u8, arg, "--version")) {
            options.version = try parser.value();
        } else if (mode == .public_key and std.mem.eql(u8, arg, "--cert-authority")) {
            options.cert_authority = true;
        } else {
            return error.UnknownOption;
        }
    }
    if (options.vault_url.len == 0) return error.MissingVaultUrl;
    if (options.key_name.len == 0) return error.MissingKeyName;
    if (options.bits != 2048 and options.bits != 3072 and options.bits != 4096) {
        return error.InvalidCaKeySize;
    }
    try azure_key_vault.validateVaultUrl(options.vault_url, options.cloud);
    return options;
}

const Profile = enum {
    interactive,
    none,
};

const SignOptions = struct {
    vault_url: []const u8,
    key_name: []const u8,
    cloud: azure_key_vault.Cloud = .public,
    version: ?[]const u8 = null,
    latest: bool = false,
    subject_key_path: []const u8,
    output_path: ?[]const u8 = null,
    key_id: []const u8,
    principals: []const []const u8,
    ttl: ?u64 = null,
    profile: Profile = .interactive,
    force_command: ?[]const u8 = null,
    source_address: ?[]const u8 = null,
    comment: ?[]const u8 = null,
    permit_agent_forwarding: bool = false,
    permit_port_forwarding: bool = false,
    permit_pty: bool = false,
    permit_user_rc: bool = false,
    permit_x11_forwarding: bool = false,
};

fn parseSignOptions(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !SignOptions {
    var principals: std.ArrayList([]const u8) = .empty;
    defer principals.deinit(allocator);
    var options = SignOptions{
        .vault_url = "",
        .key_name = "",
        .subject_key_path = "",
        .key_id = "",
        .principals = &.{},
    };
    var parser = ArgParser.init(args);
    while (parser.next()) |arg| {
        if (std.mem.eql(u8, arg, "--vault-url")) {
            options.vault_url = try parser.value();
        } else if (std.mem.eql(u8, arg, "--name") or
            std.mem.eql(u8, arg, "--key-name"))
        {
            options.key_name = try parser.value();
        } else if (std.mem.eql(u8, arg, "--cloud")) {
            options.cloud = try azure_key_vault.Cloud.parse(try parser.value());
        } else if (std.mem.eql(u8, arg, "--version")) {
            options.version = try parser.value();
        } else if (std.mem.eql(u8, arg, "--latest")) {
            options.latest = true;
        } else if (std.mem.eql(u8, arg, "--subject-key")) {
            options.subject_key_path = try parser.value();
        } else if (std.mem.eql(u8, arg, "--output")) {
            options.output_path = try parser.value();
        } else if (std.mem.eql(u8, arg, "--key-id")) {
            options.key_id = try parser.value();
        } else if (std.mem.eql(u8, arg, "--principal")) {
            try principals.append(allocator, try parser.value());
        } else if (std.mem.eql(u8, arg, "--ttl")) {
            options.ttl = std.fmt.parseInt(u64, try parser.value(), 10) catch
                return error.InvalidTtl;
        } else if (std.mem.eql(u8, arg, "--profile")) {
            const value = try parser.value();
            options.profile = if (std.mem.eql(u8, value, "interactive"))
                .interactive
            else if (std.mem.eql(u8, value, "none"))
                .none
            else
                return error.InvalidProfile;
        } else if (std.mem.eql(u8, arg, "--force-command")) {
            options.force_command = try parser.value();
        } else if (std.mem.eql(u8, arg, "--source-address")) {
            options.source_address = try parser.value();
        } else if (std.mem.eql(u8, arg, "--comment")) {
            options.comment = try parser.value();
        } else if (std.mem.eql(u8, arg, "--permit-agent-forwarding")) {
            options.permit_agent_forwarding = true;
        } else if (std.mem.eql(u8, arg, "--permit-port-forwarding")) {
            options.permit_port_forwarding = true;
        } else if (std.mem.eql(u8, arg, "--permit-pty")) {
            options.permit_pty = true;
        } else if (std.mem.eql(u8, arg, "--permit-user-rc")) {
            options.permit_user_rc = true;
        } else if (std.mem.eql(u8, arg, "--permit-x11-forwarding")) {
            options.permit_x11_forwarding = true;
        } else {
            return error.UnknownOption;
        }
    }

    if (options.vault_url.len == 0) return error.MissingVaultUrl;
    if (options.key_name.len == 0) return error.MissingKeyName;
    if (options.subject_key_path.len == 0) return error.MissingSubjectKey;
    if (options.key_id.len == 0) return error.MissingKeyId;
    if (principals.items.len == 0) return error.MissingPrincipals;
    if (principals.items.len > certificate.max_principals) return error.TooManyPrincipals;
    if (options.version != null and options.latest) return error.ConflictingKeyVersion;
    if (options.ttl) |ttl| {
        if (ttl == 0) return error.InvalidTtl;
        if (ttl > policy.maximum_ttl_seconds) return error.ValidityTooLong;
    }
    try azure_key_vault.validateVaultUrl(options.vault_url, options.cloud);
    options.principals = try principals.toOwnedSlice(allocator);
    return options;
}

const ArgParser = struct {
    args: []const []const u8,
    index: usize = 0,

    fn init(args: []const []const u8) ArgParser {
        return .{ .args = args };
    }

    fn next(self: *ArgParser) ?[]const u8 {
        if (self.index >= self.args.len) return null;
        defer self.index += 1;
        return self.args[self.index];
    }

    fn value(self: *ArgParser) ![]const u8 {
        return self.next() orelse error.MissingOptionValue;
    }
};

const AzureRuntime = struct {
    allocator: std.mem.Allocator,
    environment: std.process.Environ.Map,
    transport: azure_core.http.StdHttpTransport,
    credential: azure_credential.Credential,
    key_client: keys.KeyClient,

    fn create(
        allocator: std.mem.Allocator,
        init: std.process.Init,
        vault_url: []const u8,
        cloud: azure_key_vault.Cloud,
    ) !*AzureRuntime {
        try azure_key_vault.validateVaultUrl(vault_url, cloud);
        const self = try allocator.create(AzureRuntime);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.environment = try init.environ_map.clone(allocator);
        errdefer self.environment.deinit();
        try self.environment.put("AZURE_AUTHORITY_HOST", cloud.authorityHost());

        self.transport = azure_core.http.StdHttpTransport.init(allocator, init.io);
        errdefer self.transport.deinit();
        self.credential = try azure_credential.Credential.init(
            allocator,
            init.io,
            self.transport.asTransport(),
            self.environment,
        );
        errdefer self.credential.deinit();
        self.key_client = try keys.KeyClient.init(
            allocator,
            vault_url,
            self.credential.asCredential(),
            self.transport.asTransport(),
            .{ .scope = cloud.keyVaultScope() },
        );
        return self;
    }

    fn deinit(self: *AzureRuntime) void {
        const allocator = self.allocator;
        self.key_client.deinit();
        self.credential.deinit();
        self.transport.deinit();
        self.environment.deinit();
        allocator.destroy(self);
    }
};

fn executeEnsure(
    init: std.process.Init,
    options: CaOptions,
    stdout: *std.Io.Writer,
) !ExitCode {
    const allocator = init.arena.allocator();
    var runtime = try AzureRuntime.create(allocator, init, options.vault_url, options.cloud);
    defer runtime.deinit();
    var ca_key = try azure_key_vault.ensureCaKey(
        allocator,
        init.io,
        &runtime.key_client,
        options.vault_url,
        options.cloud,
        options.key_name,
        .{ .bits = options.bits, .hsm = options.hsm },
    );
    defer ca_key.deinit();
    const formatted = try ca_key.public_key.formatAuthorizedKey(allocator);
    defer allocator.free(formatted);
    try stdout.print(
        "Key ID: {s}\nVersion: {s}\nCA public key: {s}\n",
        .{ ca_key.key_id, ca_key.version, formatted },
    );
    return .success;
}

fn executeRotate(
    init: std.process.Init,
    options: CaOptions,
    stdout: *std.Io.Writer,
) !ExitCode {
    const allocator = init.arena.allocator();
    var runtime = try AzureRuntime.create(allocator, init, options.vault_url, options.cloud);
    defer runtime.deinit();
    var rotation = try azure_key_vault.rotateCaKey(
        allocator,
        init.io,
        &runtime.key_client,
        options.vault_url,
        options.cloud,
        options.key_name,
        .{ .bits = options.bits, .hsm = options.hsm },
    );
    defer rotation.deinit();
    const previous_formatted = try rotation.previous.public_key.formatAuthorizedKey(allocator);
    defer allocator.free(previous_formatted);
    const current_formatted = try rotation.current.public_key.formatAuthorizedKey(allocator);
    defer allocator.free(current_formatted);
    try stdout.print(
        "Previous version: {s}\nPrevious CA public key: {s}\nCurrent version: {s}\nCurrent key ID: {s}\nCurrent CA public key: {s}\nActive signing version was not changed; update it explicitly after distributing the new CA public key.\n",
        .{
            rotation.previous.version,
            previous_formatted,
            rotation.current.version,
            rotation.current.key_id,
            current_formatted,
        },
    );
    return .success;
}

fn executePublicKey(
    init: std.process.Init,
    options: CaOptions,
    stdout: *std.Io.Writer,
) !ExitCode {
    const allocator = init.arena.allocator();
    var runtime = try AzureRuntime.create(allocator, init, options.vault_url, options.cloud);
    defer runtime.deinit();
    var ca_key = try azure_key_vault.getCaKey(
        allocator,
        init.io,
        &runtime.key_client,
        options.vault_url,
        options.cloud,
        options.key_name,
        options.version,
    );
    defer ca_key.deinit();
    const formatted = if (options.cert_authority)
        try ca_key.public_key.formatCertAuthority(allocator)
    else
        try ca_key.public_key.formatAuthorizedKey(allocator);
    defer allocator.free(formatted);
    try stdout.print("{s}\n", .{formatted});
    return .success;
}

fn executeSign(
    init: std.process.Init,
    options: SignOptions,
    stdout: *std.Io.Writer,
) !ExitCode {
    const allocator = init.arena.allocator();
    const key_text = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        options.subject_key_path,
        allocator,
        .limited(public_key.max_authorized_key_len),
    );
    var subject_key = try public_key.parseAuthorizedKey(allocator, key_text);
    defer subject_key.deinit(allocator);

    const active_version = if (options.version) |version|
        version
    else if (options.latest)
        null
    else
        init.environ_map.get("SSHCA_ACTIVE_KEY_VERSION") orelse
            return error.MissingActiveKeyVersion;

    var runtime = try AzureRuntime.create(allocator, init, options.vault_url, options.cloud);
    defer runtime.deinit();
    var ca_key = try azure_key_vault.getCaKey(
        allocator,
        init.io,
        &runtime.key_client,
        options.vault_url,
        options.cloud,
        options.key_name,
        active_version,
    );
    defer ca_key.deinit();

    var key_vault_signer = try azure_key_vault.AzureKeyVaultSigner.init(
        allocator,
        options.cloud,
        &ca_key,
        runtime.credential.asCredential(),
        runtime.transport.asTransport(),
    );
    defer key_vault_signer.deinit();

    var critical_options: [2]certificate.CriticalOption = undefined;
    var critical_count: usize = 0;
    if (options.force_command) |value| {
        critical_options[critical_count] = .{ .force_command = value };
        critical_count += 1;
    }
    if (options.source_address) |value| {
        critical_options[critical_count] = .{ .source_address = value };
        critical_count += 1;
    }

    var extensions: [5]certificate.Extension = undefined;
    var extension_count: usize = 0;
    if (options.permit_agent_forwarding) appendExtension(
        &extensions,
        &extension_count,
        .permit_agent_forwarding,
    );
    if (options.permit_port_forwarding) appendExtension(
        &extensions,
        &extension_count,
        .permit_port_forwarding,
    );
    if (options.profile == .interactive or options.permit_pty) appendExtension(
        &extensions,
        &extension_count,
        .permit_pty,
    );
    if (options.permit_user_rc) appendExtension(
        &extensions,
        &extension_count,
        .permit_user_rc,
    );
    if (options.permit_x11_forwarding) appendExtension(
        &extensions,
        &extension_count,
        .permit_x11_forwarding,
    );

    var issued = try (issuer.Issuer{ .io = init.io }).issue(allocator, .{
        .subject_key = &subject_key,
        .ca_key = &ca_key,
        .versioned_signer = key_vault_signer.versionedSigner(),
        .key_id = options.key_id,
        .principals = options.principals,
        .requested_ttl = options.ttl,
        .critical_options = critical_options[0..critical_count],
        .extensions = extensions[0..extension_count],
        .comment = options.comment orelse subject_key.comment(),
    });
    defer issued.deinit();

    const output_path = options.output_path orelse
        try defaultCertificatePath(allocator, options.subject_key_path);
    try writeFileAtomic(init.io, output_path, issued.authorized_key);
    try stdout.print(
        "Wrote: {s}\nCA key version: {s}\nSerial: {d}\nValid after: {d}\nValid before: {d}\nSubject: {s}\n",
        .{
            output_path,
            issued.audit.ca_key_version,
            issued.audit.serial,
            issued.audit.valid_after,
            issued.audit.valid_before,
            issued.audit.subject_fingerprint,
        },
    );
    return .success;
}

fn appendExtension(
    extensions: *[5]certificate.Extension,
    count: *usize,
    extension: certificate.Extension,
) void {
    extensions[count.*] = extension;
    count.* += 1;
}

fn defaultCertificatePath(
    allocator: std.mem.Allocator,
    subject_key_path: []const u8,
) ![]u8 {
    const stem = if (std.mem.endsWith(u8, subject_key_path, ".pub"))
        subject_key_path[0 .. subject_key_path.len - 4]
    else
        subject_key_path;
    return std.fmt.allocPrint(allocator, "{s}-cert.pub", .{stem});
}

fn writeFileAtomic(io: std.Io, output_path: []const u8, contents: []const u8) !void {
    const directory_name = std.fs.path.dirname(output_path);
    const basename = std.fs.path.basename(output_path);
    var directory = if (directory_name) |name|
        try std.Io.Dir.cwd().openDir(io, name, .{})
    else
        std.Io.Dir.cwd();
    defer if (directory_name != null) directory.close(io);

    var atomic_file = try directory.createFileAtomic(
        io,
        basename,
        .{ .replace = true },
    );
    defer atomic_file.deinit(io);
    try atomic_file.file.writeStreamingAll(io, contents);
    try atomic_file.file.writeStreamingAll(io, "\n");
    try atomic_file.replace(io);
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "-h") or
        std.mem.eql(u8, value, "--help") or
        std.mem.eql(u8, value, "help");
}

fn writeHelp(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\Usage: sshca <command> [options]
        \\
        \\Commands:
        \\  ca ensure       Create or reuse an Azure Key Vault CA key
        \\  ca rotate       Create a new CA key version
        \\  ca public-key   Export the CA public key
        \\  sign            Sign an OpenSSH user certificate
        \\
        \\Required Azure options:
        \\  --vault-url URL  Azure Key Vault URL
        \\  --name NAME      Key Vault key name
        \\  --cloud CLOUD    public, government, or china (default: public)
        \\
    );
}

test "sign parser enforces explicit version selection and TTL limits" {
    const allocator = std.testing.allocator;
    const base = [_][]const u8{
        "--vault-url",
        "https://vm17kv.vault.azure.net",
        "--key-name",
        "ssh-ca",
        "--subject-key",
        "id_ed25519.pub",
        "--key-id",
        "alice@example",
        "--principal",
        "alice",
        "--version",
        "v1",
        "--latest",
    };
    try std.testing.expectError(
        error.ConflictingKeyVersion,
        parseSignOptions(allocator, &base),
    );

    const excessive_ttl = [_][]const u8{
        "--vault-url",
        "https://vm17kv.vault.azure.net",
        "--key-name",
        "ssh-ca",
        "--subject-key",
        "id_ed25519.pub",
        "--key-id",
        "alice@example",
        "--principal",
        "alice",
        "--ttl",
        "28801",
    };
    try std.testing.expectError(
        error.ValidityTooLong,
        parseSignOptions(allocator, &excessive_ttl),
    );
}

test "default certificate output follows OpenSSH identity naming" {
    const path = try defaultCertificatePath(std.testing.allocator, "id_ed25519.pub");
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("id_ed25519-cert.pub", path);
}
