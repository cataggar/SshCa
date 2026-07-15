const std = @import("std");
const sshca = @import("sshca");

pub fn main(init: std.process.Init) void {
    const exit_code = run(init) catch |err| switch (err) {
        error.WriteFailed => sshca.cli.ExitCode.failure,
        else => code: {
            std.debug.print("sshca: {s}\n", .{@errorName(err)});
            break :code sshca.cli.ExitCode.failure;
        },
    };

    if (exit_code != .success) {
        std.process.exit(@intFromEnum(exit_code));
    }
}

fn run(init: std.process.Init) !sshca.cli.ExitCode {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_file_writer: std.Io.File.Writer = .init(.stderr(), init.io, &stderr_buffer);
    const stderr = &stderr_file_writer.interface;

    const exit_code = sshca.cli.run(init, args, stdout, stderr) catch |err| code: {
        try stderr.print("sshca: {s}\n", .{@errorName(err)});
        break :code sshca.cli.ExitCode.failure;
    };

    try stdout.flush();
    try stderr.flush();
    return exit_code;
}
