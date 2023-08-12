const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const minisign = b.addExecutable(.{
        .name = "minisign",
        .target = target,
        .optimize = optimize,
    });
    minisign.linkLibC();
    minisign.addLibraryPath(.{ .path = "/opt/homebrew/lib" });
    minisign.addLibraryPath(.{ .path = "/usr/local/lib" });
    minisign.linkSystemLibrary("sodium");

    minisign.addIncludePath(.{ .path = "src" });
    minisign.addSystemIncludePath(.{ .path = "/opt/homebrew/include" });
    minisign.addSystemIncludePath(.{ .path = "/usr/local/include" });
    minisign.defineCMacro("_GNU_SOURCE", "1");
    minisign.addCSourceFiles(&.{ "src/base64.c", "src/get_line.c", "src/helpers.c", "src/minisign.c" }, &.{});

    b.installArtifact(minisign);
}
