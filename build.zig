const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const azure_sdk = b.dependency("azure_sdk", .{
        .target = target,
        .optimize = optimize,
    });
    const azure_core = azure_sdk.module("azure_core");
    const azure_keyvault_keys = azure_sdk.module("azure_keyvault_keys");

    const sshca_module = b.addModule("sshca", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "azure_core", .module = azure_core },
            .{ .name = "azure_keyvault_keys", .module = azure_keyvault_keys },
        },
    });

    const cli_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sshca", .module = sshca_module },
        },
    });
    const cli = b.addExecutable(.{
        .name = "sshca",
        .root_module = cli_module,
    });
    b.installArtifact(cli);

    const run_step = b.step("run", "Run the sshca CLI");
    const run_command = b.addRunArtifact(cli);
    run_command.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_command.addArgs(args);
    run_step.dependOn(&run_command.step);

    const library_tests = b.addTest(.{
        .root_module = sshca_module,
    });
    const run_library_tests = b.addRunArtifact(library_tests);

    const cli_tests = b.addTest(.{
        .root_module = cli_module,
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);

    const fixtures_module = b.createModule(.{
        .root_source_file = b.path("tests/fixtures/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sshca", .module = sshca_module },
            .{ .name = "fixtures", .module = fixtures_module },
        },
    });
    const unit_tests = b.addTest(.{
        .root_module = unit_test_module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const certificate_test_module = b.createModule(.{
        .root_source_file = b.path("tests/certificate.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sshca", .module = sshca_module },
            .{ .name = "fixtures", .module = fixtures_module },
        },
    });
    const certificate_tests = b.addTest(.{
        .root_module = certificate_test_module,
    });
    const run_certificate_tests = b.addRunArtifact(certificate_tests);

    const test_step = b.step("test", "Run core library and CLI tests");
    test_step.dependOn(&run_library_tests.step);
    test_step.dependOn(&run_cli_tests.step);
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_certificate_tests.step);

    const with_openssh = b.option(
        bool,
        "with-openssh",
        "Build the pinned Linux OpenSSH reference artifact for integration tests",
    ) orelse (target.result.os.tag == .linux);
    const integration_options = b.addOptions();
    var openssh_artifact: ?*std.Build.Step.Compile = null;
    if (with_openssh) {
        if (target.result.os.tag != .linux) {
            @panic("-Dwith-openssh=true is supported only for Linux targets");
        }
        const openssh = b.lazyDependency("openssh_portable", .{
            .target = target,
            .optimize = optimize,
        }) orelse return;
        openssh_artifact = openssh.artifact("ssh-keygen");
        integration_options.addOptionPath(
            "ssh_keygen_path",
            openssh_artifact.?.getEmittedBin(),
        );
    } else {
        integration_options.addOption([]const u8, "ssh_keygen_path", "ssh-keygen");
    }
    const test_options_module = integration_options.createModule();

    const openssl_signer_module = b.createModule(.{
        .root_source_file = b.path("tests/support/openssl_signer.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sshca", .module = sshca_module },
        },
    });
    openssl_signer_module.link_libc = true;
    openssl_signer_module.linkSystemLibrary("openssl", .{
        .use_pkg_config = .force,
    });

    const integration_test_module = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sshca", .module = sshca_module },
            .{ .name = "fixtures", .module = fixtures_module },
            .{ .name = "openssl_signer", .module = openssl_signer_module },
            .{ .name = "test_options", .module = test_options_module },
        },
    });
    const integration_tests = b.addTest(.{
        .root_module = integration_test_module,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const integration_step = b.step("integration-test", "Run OpenSSH interoperability tests");
    integration_step.dependOn(&run_integration_tests.step);
    if (openssh_artifact) |artifact| integration_step.dependOn(&artifact.step);

    const material_generator_module = b.createModule(.{
        .root_source_file = b.path("tests/integration/material_generator.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sshca", .module = sshca_module },
            .{ .name = "openssl_signer", .module = openssl_signer_module },
        },
    });
    const material_generator = b.addExecutable(.{
        .name = "sshca-integration-material",
        .root_module = material_generator_module,
    });
    const run_sshd_login = b.addSystemCommand(&.{"bash"});
    run_sshd_login.addFileArg(b.path("tests/integration/sshd-login.sh"));
    run_sshd_login.addArtifactArg(material_generator);

    const sshd_login_step = b.step(
        "sshd-login-test",
        "Run isolated certificate authentication tests against a pinned sshd",
    );
    sshd_login_step.dependOn(&run_sshd_login.step);
    const with_sshd = b.option(
        bool,
        "with-sshd",
        "Include the containerized sshd login matrix in integration-test",
    ) orelse false;
    if (with_sshd) integration_step.dependOn(&run_sshd_login.step);

    const live_azure_step = b.step("live-azure-test", "Run opt-in Azure Key Vault tests");
    const live_azure = b.option(
        bool,
        "live-azure",
        "Run credentialed Key Vault signing and containerized SSH login",
    ) orelse false;
    if (live_azure) {
        const live_keyvault_module = b.createModule(.{
            .root_source_file = b.path("tests/live/keyvault.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sshca", .module = sshca_module },
                .{ .name = "fixtures", .module = fixtures_module },
                .{ .name = "azure_core", .module = azure_core },
                .{ .name = "azure_keyvault_keys", .module = azure_keyvault_keys },
                .{ .name = "test_options", .module = test_options_module },
            },
        });
        const live_keyvault = b.addExecutable(.{
            .name = "sshca-live-keyvault",
            .root_module = live_keyvault_module,
        });
        const run_live_keyvault = b.addRunArtifact(live_keyvault);

        const run_live_login = b.addSystemCommand(&.{"bash"});
        run_live_login.addFileArg(b.path("tests/integration/sshd-login.sh"));
        run_live_login.addArg("--azure");
        run_live_login.addArtifactArg(cli);
        run_live_login.step.dependOn(&run_live_keyvault.step);
        live_azure_step.dependOn(&run_live_login.step);
    } else {
        live_azure_step.dependOn(&b.addFail(
            "live-azure-test requires -Dlive-azure=true and SSHCA_TEST_* environment variables",
        ).step);
    }
}
