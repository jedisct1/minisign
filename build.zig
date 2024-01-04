const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const minisign = b.addExecutable(.{
        .name = "minisign",
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    minisign.linkLibC();
    minisign.addLibraryPath(.{ .path = "/opt/homebrew/lib" });
    minisign.addLibraryPath(.{ .path = "/usr/local/lib" });
    minisign.linkSystemLibrary("sodium");

    minisign.addIncludePath(.{ .path = "src" });
    minisign.addSystemIncludePath(.{ .path = "/opt/homebrew/include" });
    minisign.addSystemIncludePath(.{ .path = "/usr/local/include" });
    minisign.defineCMacro("_GNU_SOURCE", "1");
    const source_files = &.{ "src/base64.c", "src/get_line.c", "src/helpers.c", "src/minisign.c" };
    minisign.addCSourceFiles(.{ .files = source_files });

    b.installArtifact(minisign);
}
