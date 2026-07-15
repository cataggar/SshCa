const std = @import("std");
const azure_core = @import("azure_core");
const keys = @import("azure_keyvault_keys");
const public_key = @import("public_key.zig");
const signer = @import("signer.zig");

pub const operation_id_tag = "sshca-operation-id";
pub const purpose_tag = "sshca-purpose";
pub const purpose_value = "openssh-certificate-authority";
pub const repository_tag = "sshca-repository";
pub const repository_value = "cataggar/SshCa";

pub const Cloud = enum {
    public,
    government,
    china,

    pub fn parse(value: []const u8) !Cloud {
        if (std.mem.eql(u8, value, "public")) return .public;
        if (std.mem.eql(u8, value, "government")) return .government;
        if (std.mem.eql(u8, value, "china")) return .china;
        return error.InvalidCloud;
    }

    pub fn authorityHost(self: Cloud) []const u8 {
        return switch (self) {
            .public => "https://login.microsoftonline.com/",
            .government => "https://login.microsoftonline.us/",
            .china => "https://login.chinacloudapi.cn/",
        };
    }

    pub fn keyVaultScope(self: Cloud) []const u8 {
        return switch (self) {
            .public => "https://vault.azure.net/.default",
            .government => "https://vault.usgovcloudapi.net/.default",
            .china => "https://vault.azure.cn/.default",
        };
    }

    fn keyVaultSuffix(self: Cloud) []const u8 {
        return switch (self) {
            .public => "vault.azure.net",
            .government => "vault.usgovcloudapi.net",
            .china => "vault.azure.cn",
        };
    }
};

pub const ProvisionOptions = struct {
    bits: u16 = 3072,
    hsm: bool = false,
    operation_id: ?[]const u8 = null,
};

pub const CaKey = struct {
    allocator: std.mem.Allocator,
    vault_url: []u8,
    key_id: []u8,
    name: []u8,
    version: []u8,
    public_key: public_key.PublicKey,

    pub fn deinit(self: *CaKey) void {
        self.public_key.deinit(self.allocator);
        self.allocator.free(self.vault_url);
        self.allocator.free(self.key_id);
        self.allocator.free(self.name);
        self.allocator.free(self.version);
        self.* = undefined;
    }
};

pub const Rotation = struct {
    previous: CaKey,
    current: CaKey,

    pub fn deinit(self: *Rotation) void {
        self.previous.deinit();
        self.current.deinit();
        self.* = undefined;
    }
};

pub fn validateVaultUrl(vault_url: []const u8, cloud: Cloud) !void {
    const uri = std.Uri.parse(vault_url) catch return error.InvalidVaultUrl;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        return error.InvalidVaultUrl;
    }
    if (uri.user != null or uri.password != null or uri.query != null or uri.fragment != null) {
        return error.InvalidVaultUrl;
    }
    if (uri.port) |port| {
        if (port != 443) return error.InvalidVaultUrl;
    }
    const host_component = uri.host orelse return error.InvalidVaultUrl;
    const host = host_component.percent_encoded;
    const suffix = cloud.keyVaultSuffix();
    if (host.len <= suffix.len + 1) return error.InvalidVaultUrl;
    const suffix_start = host.len - suffix.len;
    if (host[suffix_start - 1] != '.' or
        !std.ascii.eqlIgnoreCase(host[suffix_start..], suffix))
    {
        return error.InvalidVaultUrl;
    }
    const vault_name = host[0 .. suffix_start - 1];
    if (!isValidVaultName(vault_name)) return error.InvalidVaultUrl;

    const path = uri.path.percent_encoded;
    if (path.len != 0 and !std.mem.eql(u8, path, "/")) return error.InvalidVaultUrl;
}

fn isValidVaultName(name: []const u8) bool {
    if (name.len < 3 or name.len > 24) return false;
    if (!std.ascii.isAlphanumeric(name[0]) or !std.ascii.isAlphanumeric(name[name.len - 1])) {
        return false;
    }
    for (name) |char| {
        if (!std.ascii.isAlphanumeric(char) and char != '-') return false;
    }
    return true;
}

pub fn getCaKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *keys.KeyClient,
    vault_url: []const u8,
    cloud: Cloud,
    name: []const u8,
    version: ?[]const u8,
) !CaKey {
    _ = io;
    try validateVaultUrl(vault_url, cloud);
    var result = if (version) |key_version|
        try client.getKeyVersionResult(allocator, name, key_version)
    else
        try client.getKeyResult(allocator, name);
    return switch (result) {
        .ok => |*key| caKeyFromResponse(allocator, vault_url, name, null, key),
        .err => |*azure_error| {
            const is_missing = azure_error.status_code == 404;
            azure_error.deinit();
            if (is_missing) return error.CaKeyNotFound;
            return error.GetCaKeyFailed;
        },
    };
}

pub fn ensureCaKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *keys.KeyClient,
    vault_url: []const u8,
    cloud: Cloud,
    name: []const u8,
    options: ProvisionOptions,
) !CaKey {
    try validateVaultUrl(vault_url, cloud);
    var result = try client.getKeyResult(allocator, name);
    switch (result) {
        .ok => |*key| return caKeyFromResponse(allocator, vault_url, name, options, key),
        .err => |*azure_error| {
            const is_missing = azure_error.status_code == 404;
            azure_error.deinit();
            if (!is_missing) return error.GetCaKeyFailed;
        },
    }

    return createCaKey(allocator, io, client, vault_url, name, options);
}

pub fn rotateCaKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *keys.KeyClient,
    vault_url: []const u8,
    cloud: Cloud,
    name: []const u8,
    options: ProvisionOptions,
) !Rotation {
    var previous = try getCaKey(
        allocator,
        io,
        client,
        vault_url,
        cloud,
        name,
        null,
    );
    errdefer previous.deinit();
    var current = try createCaKey(allocator, io, client, vault_url, name, options);
    errdefer current.deinit();
    if (std.mem.eql(u8, previous.version, current.version)) {
        return error.RotationDidNotCreateNewVersion;
    }
    return .{
        .previous = previous,
        .current = current,
    };
}

fn createCaKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *keys.KeyClient,
    vault_url: []const u8,
    name: []const u8,
    options: ProvisionOptions,
) !CaKey {
    if (options.bits != 2048 and options.bits != 3072 and options.bits != 4096) {
        return error.InvalidCaKeySize;
    }

    var generated_id: [32]u8 = undefined;
    const operation_id = options.operation_id orelse operation_id: {
        var random: [16]u8 = undefined;
        try io.randomSecure(&random);
        generated_id = std.fmt.bytesToHex(random, .lower);
        break :operation_id &generated_id;
    };
    if (operation_id.len == 0 or operation_id.len > 256) return error.InvalidOperationId;

    const tags = [_]keys.Tag{
        .{ .name = operation_id_tag, .value = operation_id },
        .{ .name = purpose_tag, .value = purpose_value },
        .{ .name = repository_tag, .value = repository_value },
    };
    const create_options = keys.CreateRsaKeyOptions{
        .key_type = if (options.hsm) .rsa_hsm else .rsa,
        .key_size = options.bits,
        .operations = &.{ .sign, .verify },
        .enabled = true,
        .exportable = false,
        .tags = &tags,
    };

    var result = client.createRsaKeyResult(allocator, name, create_options) catch {
        const reconciled = reconcileCreate(
            allocator,
            io,
            client,
            vault_url,
            name,
            operation_id,
            options,
        ) catch return error.CreateOutcomeUnknown;
        return reconciled orelse error.CreateOutcomeUnknown;
    };
    switch (result) {
        .ok => |*key| return caKeyFromResponse(allocator, vault_url, name, options, key),
        .err => |*azure_error| {
            const may_have_succeeded = azure_error.status_code == 408 or
                azure_error.status_code == 429 or
                azure_error.status_code >= 500;
            azure_error.deinit();
            if (!may_have_succeeded) return error.CreateCaKeyFailed;
            return (reconcileCreate(
                allocator,
                io,
                client,
                vault_url,
                name,
                operation_id,
                options,
            ) catch return error.CreateOutcomeUnknown) orelse error.CreateOutcomeUnknown;
        },
    }
}

fn reconcileCreate(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *keys.KeyClient,
    vault_url: []const u8,
    name: []const u8,
    operation_id: []const u8,
    options: ProvisionOptions,
) !?CaKey {
    _ = io;
    var pager = try client.listKeyVersions(allocator, name, 25);
    defer pager.deinit();

    var matching_version: ?[]u8 = null;
    defer if (matching_version) |version| allocator.free(version);

    while (try pager.next()) |items| {
        defer {
            for (items) |*item| item.deinit(allocator);
            allocator.free(items);
        }
        for (items) |item| {
            if (!hasTag(item.tags, operation_id_tag, operation_id)) continue;
            const version = item.version orelse continue;
            if (matching_version != null) return error.MultipleProvisioningMatches;
            matching_version = try allocator.dupe(u8, version);
        }
    }

    const version = matching_version orelse return null;
    var result = try client.getKeyVersionResult(allocator, name, version);
    return switch (result) {
        .ok => |*key| blk: {
            if (!hasTag(key.tags, operation_id_tag, operation_id)) {
                key.deinit(allocator);
                return error.ProvisioningTagMismatch;
            }
            break :blk try caKeyFromResponse(allocator, vault_url, name, options, key);
        },
        .err => |*azure_error| {
            azure_error.deinit();
            return error.CreateOutcomeUnknown;
        },
    };
}

fn hasTag(tags: []const keys.OwnedTag, name: []const u8, value: []const u8) bool {
    for (tags) |tag| {
        if (std.mem.eql(u8, tag.name, name) and std.mem.eql(u8, tag.value, value)) {
            return true;
        }
    }
    return false;
}

fn caKeyFromResponse(
    allocator: std.mem.Allocator,
    vault_url: []const u8,
    expected_name: []const u8,
    expected_options: ?ProvisionOptions,
    key: *keys.KeyVaultKey,
) !CaKey {
    defer key.deinit(allocator);
    try validateSafety(key.*, expected_name);
    if (expected_options) |options| try validateProvisioningMatch(key.*, options);

    const version = key.version orelse return error.MissingKeyVersion;
    try validateKeyIdentity(allocator, vault_url, key.id, expected_name, version);
    const key_path_start = std.mem.indexOf(u8, key.id, "/keys/") orelse
        return error.UnexpectedKeyId;

    const comment = try std.fmt.allocPrint(
        allocator,
        "{s}@{s}",
        .{ expected_name, version },
    );
    defer allocator.free(comment);

    var ssh_public_key = try public_key.PublicKey.initRsa(
        allocator,
        key.exponent.?,
        key.modulus.?,
        comment,
    );
    errdefer ssh_public_key.deinit(allocator);

    const owned_vault_url = try allocator.dupe(u8, key.id[0..key_path_start]);
    errdefer allocator.free(owned_vault_url);
    const key_id = try allocator.dupe(u8, key.id);
    errdefer allocator.free(key_id);
    const name = try allocator.dupe(u8, expected_name);
    errdefer allocator.free(name);
    const owned_version = try allocator.dupe(u8, version);
    errdefer allocator.free(owned_version);

    return .{
        .allocator = allocator,
        .vault_url = owned_vault_url,
        .key_id = key_id,
        .name = name,
        .version = owned_version,
        .public_key = ssh_public_key,
    };
}

fn validateSafety(
    key: keys.KeyVaultKey,
    expected_name: []const u8,
) !void {
    if (!std.mem.eql(u8, key.name, expected_name)) return error.UnexpectedKeyName;
    const key_type = key.key_type orelse return error.IncompatibleCaKeyType;
    if (key_type != .rsa and key_type != .rsa_hsm) return error.IncompatibleCaKeyType;
    const modulus = key.modulus orelse return error.MissingCaPublicKey;
    const exponent = key.exponent orelse return error.MissingCaPublicKey;
    if (modulus.len == 0 or exponent.len == 0) return error.MissingCaPublicKey;
    const modulus_bits = try rsaModulusBits(modulus);
    if (modulus_bits != 2048 and modulus_bits != 3072 and modulus_bits != 4096) {
        return error.IncompatibleCaKeySize;
    }
    if (key.properties.enabled != true) return error.CaKeyDisabled;
    if (key.properties.exportable == true) return error.ExportableCaKeyRejected;
    if (key.release_policy != null) return error.ReleasePolicyRejected;
    if (key.managed == true) return error.ManagedCaKeyRejected;
    if (key.operations.len != 2 or
        !hasOperation(key.operations, .sign) or
        !hasOperation(key.operations, .verify))
    {
        return error.IncompatibleCaKeyOperations;
    }
}

fn validateProvisioningMatch(key: keys.KeyVaultKey, options: ProvisionOptions) !void {
    const expected_type: keys.KeyType = if (options.hsm) .rsa_hsm else .rsa;
    if (key.key_type.? != expected_type) return error.IncompatibleCaKeyType;
    if (try rsaModulusBits(key.modulus.?) != options.bits) return error.IncompatibleCaKeySize;
}

fn rsaModulusBits(modulus: []const u8) !usize {
    if (modulus.len == 0) return error.MissingCaPublicKey;
    return (modulus.len - 1) * 8 + (8 - @as(usize, @intCast(@clz(modulus[0]))));
}

fn validateKeyIdentity(
    allocator: std.mem.Allocator,
    vault_url: []const u8,
    key_id: []const u8,
    expected_name: []const u8,
    expected_version: []const u8,
) !void {
    const vault_uri = std.Uri.parse(vault_url) catch return error.UnexpectedKeyId;
    const key_uri = std.Uri.parse(key_id) catch return error.UnexpectedKeyId;
    if (!std.ascii.eqlIgnoreCase(key_uri.scheme, "https") or
        key_uri.user != null or
        key_uri.password != null or
        key_uri.query != null or
        key_uri.fragment != null)
    {
        return error.UnexpectedKeyId;
    }
    const vault_host = (vault_uri.host orelse return error.UnexpectedKeyId).percent_encoded;
    const key_host = (key_uri.host orelse return error.UnexpectedKeyId).percent_encoded;
    if (!std.ascii.eqlIgnoreCase(vault_host, key_host)) return error.UnexpectedKeyId;
    if ((vault_uri.port orelse 443) != (key_uri.port orelse 443)) {
        return error.UnexpectedKeyId;
    }
    const expected_path = try std.fmt.allocPrint(
        allocator,
        "/keys/{s}/{s}",
        .{ expected_name, expected_version },
    );
    defer allocator.free(expected_path);
    if (!std.mem.eql(u8, key_uri.path.percent_encoded, expected_path)) {
        return error.UnexpectedKeyId;
    }
}

fn hasOperation(operations: []const keys.KeyOperation, expected: keys.KeyOperation) bool {
    for (operations) |operation| {
        if (operation == expected) return true;
    }
    return false;
}

pub const AzureKeyVaultSigner = struct {
    client: keys.CryptographyClient,

    pub fn init(
        allocator: std.mem.Allocator,
        cloud: Cloud,
        ca_key: *const CaKey,
        credential: *azure_core.credentials.TokenCredential,
        transport: *azure_core.http.HttpTransport,
    ) !AzureKeyVaultSigner {
        try validateVaultUrl(ca_key.vault_url, cloud);
        return .{
            .client = try keys.CryptographyClient.init(
                allocator,
                ca_key.key_id,
                credential,
                transport,
                .{ .scope = cloud.keyVaultScope() },
            ),
        };
    }

    pub fn deinit(self: *AzureKeyVaultSigner) void {
        self.client.deinit();
        self.* = undefined;
    }

    pub fn digestSigner(self: *AzureKeyVaultSigner) signer.DigestSigner {
        return signer.DigestSigner.init(self, signDigest);
    }

    pub fn versionedSigner(self: *AzureKeyVaultSigner) signer.VersionedDigestSigner {
        return signer.VersionedDigestSigner.init(self.keyId(), self.digestSigner());
    }

    pub fn keyId(self: AzureKeyVaultSigner) []const u8 {
        return self.client.key_id;
    }

    fn signDigest(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        digest: *const [64]u8,
    ) anyerror![]u8 {
        const self: *AzureKeyVaultSigner = @ptrCast(@alignCast(context));
        var signature = try self.client.sign(
            allocator,
            .rs512,
            digest,
        );
        defer signature.deinit(allocator);
        return allocator.dupe(u8, signature.bytes);
    }
};

test "vault URLs are cloud-bound before authentication" {
    try validateVaultUrl("https://vm17kv.vault.azure.net", .public);
    try validateVaultUrl("https://vm17kv.vault.usgovcloudapi.net/", .government);
    try validateVaultUrl("https://vm17kv.vault.azure.cn", .china);

    try std.testing.expectError(
        error.InvalidVaultUrl,
        validateVaultUrl("http://vm17kv.vault.azure.net", .public),
    );
    try std.testing.expectError(
        error.InvalidVaultUrl,
        validateVaultUrl("https://vm17kv.vault.azure.net.evil.example", .public),
    );
    try std.testing.expectError(
        error.InvalidVaultUrl,
        validateVaultUrl("https://vm17kv.vault.azure.net/keys/name", .public),
    );
    try std.testing.expectError(
        error.InvalidVaultUrl,
        validateVaultUrl("https://vm17kv.vault.azure.net", .government),
    );
}

test "ensure creates only after 404 and then reuses the compatible key" {
    const allocator = std.testing.allocator;
    const created = try testKeyResponse(allocator, "v1", "ensure-op", false);
    defer allocator.free(created);
    const existing = try testKeyResponse(allocator, "v1", null, false);
    defer allocator.free(existing);
    const responses = [_]azure_core.http.SequenceMockTransport.CannedResponse{
        .{
            .status = 404,
            .body = "{\"error\":{\"code\":\"KeyNotFound\",\"message\":\"missing\"}}",
        },
        .{ .status = 200, .body = created },
        .{ .status = 200, .body = existing },
    };

    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.SequenceMockTransport.init(allocator, &responses);
    var client = try keys.KeyClient.init(
        allocator,
        "https://vm17kv.vault.azure.net",
        credential.asCredential(),
        service.asTransport(),
        .{},
    );
    defer client.deinit();

    var first = try ensureCaKey(
        allocator,
        std.testing.io,
        &client,
        "https://vm17kv.vault.azure.net",
        .public,
        "ssh-ca",
        .{ .operation_id = "ensure-op" },
    );
    defer first.deinit();
    var second = try ensureCaKey(
        allocator,
        std.testing.io,
        &client,
        "https://vm17kv.vault.azure.net",
        .public,
        "ssh-ca",
        .{ .operation_id = "unused" },
    );
    defer second.deinit();

    try std.testing.expectEqual(@as(usize, 3), service.call_count);
    try std.testing.expectEqualStrings("v1", first.version);
    try std.testing.expectEqualStrings(first.key_id, second.key_id);
}

test "ambiguous create is reconciled by the unique operation tag" {
    const allocator = std.testing.allocator;
    const versions = try testVersionListResponse(allocator, "recovered", "reconcile-op");
    defer allocator.free(versions);
    const recovered = try testKeyResponse(
        allocator,
        "recovered",
        "reconcile-op",
        false,
    );
    defer allocator.free(recovered);
    const responses = [_]azure_core.http.SequenceMockTransport.CannedResponse{
        .{ .status = 404, .body = "{}" },
        .{ .status = 500, .body = "{\"error\":{\"code\":\"InternalServerError\"}}" },
        .{ .status = 200, .body = versions },
        .{ .status = 200, .body = recovered },
    };

    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.SequenceMockTransport.init(allocator, &responses);
    var client = try keys.KeyClient.init(
        allocator,
        "https://vm17kv.vault.azure.net",
        credential.asCredential(),
        service.asTransport(),
        .{},
    );
    defer client.deinit();

    var ca_key = try ensureCaKey(
        allocator,
        std.testing.io,
        &client,
        "https://vm17kv.vault.azure.net",
        .public,
        "ssh-ca",
        .{ .operation_id = "reconcile-op" },
    );
    defer ca_key.deinit();
    try std.testing.expectEqual(@as(usize, 4), service.call_count);
    try std.testing.expectEqualStrings("recovered", ca_key.version);
}

test "rotation creates exactly one distinct key version" {
    const allocator = std.testing.allocator;
    const old_key = try testKeyResponseWithShape(
        allocator,
        "old",
        null,
        false,
        256,
        "RSA",
        0x81,
    );
    defer allocator.free(old_key);
    const new_key = try testKeyResponseWithShape(
        allocator,
        "new",
        "rotate-op",
        false,
        512,
        "RSA-HSM",
        0x81,
    );
    defer allocator.free(new_key);
    const responses = [_]azure_core.http.SequenceMockTransport.CannedResponse{
        .{ .status = 200, .body = old_key },
        .{ .status = 200, .body = new_key },
    };

    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.SequenceMockTransport.init(allocator, &responses);
    var client = try keys.KeyClient.init(
        allocator,
        "https://vm17kv.vault.azure.net",
        credential.asCredential(),
        service.asTransport(),
        .{},
    );
    defer client.deinit();

    var rotation = try rotateCaKey(
        allocator,
        std.testing.io,
        &client,
        "https://vm17kv.vault.azure.net",
        .public,
        "ssh-ca",
        .{
            .bits = 4096,
            .hsm = true,
            .operation_id = "rotate-op",
        },
    );
    defer rotation.deinit();
    try std.testing.expectEqual(@as(usize, 2), service.call_count);
    try std.testing.expectEqualStrings("old", rotation.previous.version);
    try std.testing.expectEqualStrings("new", rotation.current.version);
}

test "Azure signer sends the exact RS512 digest and returns raw signature bytes" {
    const allocator = std.testing.allocator;
    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.MockTransport.init(
        allocator,
        200,
        "{\"kid\":\"https://vm17kv.vault.azure.net/keys/ssh-ca/v1\",\"value\":\"AQI\"}",
    );
    defer service.deinit();
    var ca_key = try testCaKey(allocator, "v1");
    defer ca_key.deinit();
    var key_vault_signer = try AzureKeyVaultSigner.init(
        allocator,
        .public,
        &ca_key,
        credential.asCredential(),
        service.asTransport(),
    );
    defer key_vault_signer.deinit();

    const digest = [_]u8{0x5a} ** 64;
    const signature = try key_vault_signer.digestSigner().signDigest(
        allocator,
        &digest,
    );
    defer allocator.free(signature);
    const encoded_digest = try azure_core.base64.urlEncode(allocator, &digest);
    defer allocator.free(encoded_digest);
    const expected_body = try std.fmt.allocPrint(
        allocator,
        "{{\"alg\":\"RS512\",\"value\":\"{s}\"}}",
        .{encoded_digest},
    );
    defer allocator.free(expected_body);

    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, signature);
    try std.testing.expectEqualStrings(expected_body, service.last_body.?);
}

test "incompatible existing CA keys are rejected instead of replaced" {
    const allocator = std.testing.allocator;
    const unsafe_key = try testKeyResponse(allocator, "v1", null, true);
    defer allocator.free(unsafe_key);
    const responses = [_]azure_core.http.SequenceMockTransport.CannedResponse{
        .{ .status = 200, .body = unsafe_key },
    };

    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.SequenceMockTransport.init(allocator, &responses);
    var client = try keys.KeyClient.init(
        allocator,
        "https://vm17kv.vault.azure.net",
        credential.asCredential(),
        service.asTransport(),
        .{},
    );
    defer client.deinit();

    try std.testing.expectError(
        error.ExportableCaKeyRejected,
        ensureCaKey(
            allocator,
            std.testing.io,
            &client,
            "https://vm17kv.vault.azure.net",
            .public,
            "ssh-ca",
            .{},
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), service.call_count);
}

test "ensure checks actual RSA modulus bits rather than encoded byte length" {
    const allocator = std.testing.allocator;
    const short_key = try testKeyResponseWithShape(
        allocator,
        "v1",
        null,
        false,
        384,
        "RSA",
        0x41,
    );
    defer allocator.free(short_key);
    const responses = [_]azure_core.http.SequenceMockTransport.CannedResponse{
        .{ .status = 200, .body = short_key },
    };

    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.SequenceMockTransport.init(allocator, &responses);
    var client = try keys.KeyClient.init(
        allocator,
        "https://vm17kv.vault.azure.net",
        credential.asCredential(),
        service.asTransport(),
        .{},
    );
    defer client.deinit();

    try std.testing.expectError(
        error.IncompatibleCaKeySize,
        ensureCaKey(
            allocator,
            std.testing.io,
            &client,
            "https://vm17kv.vault.azure.net",
            .public,
            "ssh-ca",
            .{},
        ),
    );
}

test "canonical service key IDs bind case-varied vault URLs with explicit HTTPS port" {
    const allocator = std.testing.allocator;
    const key_response = try testKeyResponse(allocator, "v1", null, false);
    defer allocator.free(key_response);
    const responses = [_]azure_core.http.SequenceMockTransport.CannedResponse{
        .{ .status = 200, .body = key_response },
    };

    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.SequenceMockTransport.init(allocator, &responses);
    var client = try keys.KeyClient.init(
        allocator,
        "https://VM17KV.vault.azure.net:443/",
        credential.asCredential(),
        service.asTransport(),
        .{},
    );
    defer client.deinit();

    var ca_key = try ensureCaKey(
        allocator,
        std.testing.io,
        &client,
        "https://VM17KV.vault.azure.net:443/",
        .public,
        "ssh-ca",
        .{},
    );
    defer ca_key.deinit();
    try std.testing.expectEqualStrings(
        "https://vm17kv.vault.azure.net",
        ca_key.vault_url,
    );
}

test "empty JWK RSA public values are rejected without indexing them" {
    const allocator = std.testing.allocator;
    const empty_modulus = try testKeyResponseWithShape(
        allocator,
        "v1",
        null,
        false,
        0,
        "RSA",
        0,
    );
    defer allocator.free(empty_modulus);
    const responses = [_]azure_core.http.SequenceMockTransport.CannedResponse{
        .{ .status = 200, .body = empty_modulus },
    };

    var credential_transport = azure_core.http.MockTransport.init(
        allocator,
        200,
        test_credential_response,
    );
    defer credential_transport.deinit();
    var credential = azure_core.identity.ClientSecretCredential.init(
        allocator,
        credential_transport.asTransport(),
        "tenant",
        "client",
        "secret",
    );
    var service = azure_core.http.SequenceMockTransport.init(allocator, &responses);
    var client = try keys.KeyClient.init(
        allocator,
        "https://vm17kv.vault.azure.net",
        credential.asCredential(),
        service.asTransport(),
        .{},
    );
    defer client.deinit();

    try std.testing.expectError(
        error.MissingCaPublicKey,
        ensureCaKey(
            allocator,
            std.testing.io,
            &client,
            "https://vm17kv.vault.azure.net",
            .public,
            "ssh-ca",
            .{},
        ),
    );
}

fn testKeyResponse(
    allocator: std.mem.Allocator,
    version: []const u8,
    operation_id: ?[]const u8,
    exportable: bool,
) ![]u8 {
    return testKeyResponseWithShape(
        allocator,
        version,
        operation_id,
        exportable,
        384,
        "RSA",
        0x81,
    );
}

fn testKeyResponseWithShape(
    allocator: std.mem.Allocator,
    version: []const u8,
    operation_id: ?[]const u8,
    exportable: bool,
    modulus_len: usize,
    key_type: []const u8,
    first_byte: u8,
) ![]u8 {
    const modulus = try allocator.alloc(u8, modulus_len);
    defer allocator.free(modulus);
    @memset(modulus, 0x81);
    if (modulus.len != 0) modulus[0] = first_byte;
    const encoded_modulus = try azure_core.base64.urlEncode(allocator, modulus);
    defer allocator.free(encoded_modulus);
    const tag = if (operation_id) |value|
        try std.fmt.allocPrint(
            allocator,
            ",\"tags\":{{\"{s}\":\"{s}\"}}",
            .{ operation_id_tag, value },
        )
    else
        try allocator.dupe(u8, "");
    defer allocator.free(tag);
    return std.fmt.allocPrint(
        allocator,
        "{{\"key\":{{\"kid\":\"https://vm17kv.vault.azure.net/keys/ssh-ca/{s}\",\"kty\":\"{s}\",\"key_ops\":[\"sign\",\"verify\"],\"n\":\"{s}\",\"e\":\"AQAB\"}},\"attributes\":{{\"enabled\":true,\"exportable\":{s}}}{s},\"managed\":false}}",
        .{
            version,
            key_type,
            encoded_modulus,
            if (exportable) "true" else "false",
            tag,
        },
    );
}

fn testVersionListResponse(
    allocator: std.mem.Allocator,
    version: []const u8,
    operation_id: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"value\":[{{\"kid\":\"https://vm17kv.vault.azure.net/keys/ssh-ca/{s}\",\"attributes\":{{\"enabled\":true,\"exportable\":false}},\"tags\":{{\"{s}\":\"{s}\"}},\"managed\":false}}]}}",
        .{ version, operation_id_tag, operation_id },
    );
}

fn testCaKey(allocator: std.mem.Allocator, version: []const u8) !CaKey {
    const exponent = [_]u8{ 0x01, 0x00, 0x01 };
    const modulus = [_]u8{0x81} ** 384;
    var ssh_public_key = try public_key.PublicKey.initRsa(
        allocator,
        &exponent,
        &modulus,
        "",
    );
    errdefer ssh_public_key.deinit(allocator);
    const vault_url = try allocator.dupe(u8, "https://vm17kv.vault.azure.net");
    errdefer allocator.free(vault_url);
    const key_id = try std.fmt.allocPrint(
        allocator,
        "https://vm17kv.vault.azure.net/keys/ssh-ca/{s}",
        .{version},
    );
    errdefer allocator.free(key_id);
    const name = try allocator.dupe(u8, "ssh-ca");
    errdefer allocator.free(name);
    const owned_version = try allocator.dupe(u8, version);
    errdefer allocator.free(owned_version);
    return .{
        .allocator = allocator,
        .vault_url = vault_url,
        .key_id = key_id,
        .name = name,
        .version = owned_version,
        .public_key = ssh_public_key,
    };
}

const test_credential_response =
    \\{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}
;
