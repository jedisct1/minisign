const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const use_libzodium = b.option(bool, "without_libsodium", "Use the zig standard library instead of libsodium") orelse false;
    const use_static_linking = b.option(bool, "static", "Statically link the binary") orelse false;

    const minisign = b.addExecutable(.{
        .name = "minisign",
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    minisign.linkLibC();
    if (use_libzodium) {
        const libzodium_mod = b.createModule(.{
            .root_source_file = b.path("src/libzodium.zig"),
            .target = target,
            .optimize = optimize,
        });
        const libzodium = b.addStaticLibrary(.{
            .name = "zodium",
            .root_module = libzodium_mod,
            .strip = true,
        });
        libzodium.linkLibC();
        b.installArtifact(libzodium);
        minisign.root_module.addCMacro("LIBZODIUM", "1");
        minisign.linkLibrary(libzodium);
    } else {
        minisign.root_module.linkSystemLibrary(
            "sodium",
            .{
                .use_pkg_config = .yes,
                .preferred_link_mode = if (use_static_linking) .static else .dynamic,
            },
        );
    }
    minisign.addIncludePath(b.path("src"));
    minisign.addSystemIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    minisign.addSystemIncludePath(.{ .cwd_relative = "/usr/local/include" });
    minisign.root_module.addCMacro("_GNU_SOURCE", "1");
    const source_files = &.{ "src/base64.c", "src/get_line.c", "src/helpers.c", "src/minisign.c" };
    minisign.addCSourceFiles(.{ .files = source_files });

    b.installArtifact(minisign);
}
