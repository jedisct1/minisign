const builtin = @import("builtin");
const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const use_libzodium = b.option(bool, "without-libsodium", "Use the zig standard library instead of libsodium") orelse false;
    const use_static_linking = b.option(bool, "static", "Statically link the binary") orelse false;

    const minisign = b.addExecutable(.{
        .name = "minisign",
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    minisign.linkLibC();
    if (use_libzodium) {
        var libzodium = lib: {
            if (builtin.zig_version.major == 0 and builtin.zig_version.minor < 13) {
                @compileError("Building requires Zig 0.13.0 or later");
            }
            if (builtin.zig_version.major == 0 and builtin.zig_version.minor == 13) {
                break :lib b.addStaticLibrary(.{
                    .name = "zodium",
                    .strip = true,
                    .root_source_file = b.path("src/libzodium/libzodium.zig"),
                    .target = target,
                    .optimize = optimize,
                });
            } else {
                const libzodium_mod = b.createModule(.{
                    .root_source_file = b.path("src/libzodium/libzodium.zig"),
                    .target = target,
                    .optimize = optimize,
                });
                break :lib b.addStaticLibrary(.{
                    .name = "zodium",
                    .root_module = libzodium_mod,
                    .strip = true,
                });
            }
        };
        libzodium.linkLibC();
        b.installArtifact(libzodium);
        minisign.root_module.addCMacro("LIBZODIUM", "1");
        minisign.linkLibrary(libzodium);
    } else {
        var override_pkgconfig = false;
        if (std.posix.getenv("LIBSODIUM_INCLUDE_PATH")) |path| {
            minisign.addSystemIncludePath(.{ .cwd_relative = path });
            override_pkgconfig = true;
        }
        if (std.posix.getenv("LIBSODIUM_LIB_PATH")) |path| {
            minisign.addLibraryPath(.{ .cwd_relative = path });
            override_pkgconfig = true;
        }
        minisign.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        minisign.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
        minisign.root_module.linkSystemLibrary(
            "sodium",
            .{
                .use_pkg_config = if (override_pkgconfig) .no else .yes,
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
