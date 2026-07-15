const std = @import("std");
const azure_core = @import("azure_core");

pub const environment_variable = "SSHCA_AZURE_CREDENTIAL";

pub const Mode = enum {
    default,
    azure_cli,

    pub fn parse(value: []const u8) !Mode {
        if (std.mem.eql(u8, value, "default")) return .default;
        if (std.mem.eql(u8, value, "azure-cli")) return .azure_cli;
        return error.InvalidAzureCredentialMode;
    }
};

pub const Credential = union(enum) {
    default: azure_core.identity.DefaultAzureCredential,
    azure_cli: azure_core.identity.AzureCliCredential,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        transport: *azure_core.http.HttpTransport,
        environment: anytype,
    ) !Credential {
        const mode = try Mode.parse(environment.get(environment_variable) orelse "default");
        return switch (mode) {
            .default => .{
                .default = try azure_core.identity.DefaultAzureCredential.init(
                    allocator,
                    io,
                    transport,
                    environment,
                ),
            },
            .azure_cli => .{
                .azure_cli = azure_core.identity.AzureCliCredential.init(allocator, io),
            },
        };
    }

    pub fn asCredential(
        self: *Credential,
    ) *azure_core.credentials.TokenCredential {
        return switch (self.*) {
            .default => |*credential| credential.asCredential(),
            .azure_cli => |*credential| credential.asCredential(),
        };
    }

    pub fn deinit(self: *Credential) void {
        switch (self.*) {
            .default => |*credential| credential.deinit(),
            .azure_cli => {},
        }
        self.* = undefined;
    }
};

test "credential mode parsing is explicit" {
    try std.testing.expectEqual(Mode.default, try Mode.parse("default"));
    try std.testing.expectEqual(Mode.azure_cli, try Mode.parse("azure-cli"));
    try std.testing.expectError(
        error.InvalidAzureCredentialMode,
        Mode.parse("managed-identity"),
    );
}
