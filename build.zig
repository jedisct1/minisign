const builtin = @import("builtin");
const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const use_libzodium = b.option(bool, "without-libsodium", "Use the zig standard library instead of libsodium") orelse false;
    const use_static_linking = b.option(bool, "static", "Statically link the binary") orelse false;

    const minisign = b.addExecutable(.{
        .name = "minisign",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    if (builtin.zig_version.major == 0 and builtin.zig_version.minor < 15) {
        @compileError("Building requires Zig 0.15.1 or later");
    }

    // fix Mach-O relocation
    minisign.headerpad_max_install_names = true;

    if (use_libzodium) {
        const libzodium = lib: {
            break :lib b.addLibrary(.{
                .name = "zodium",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/libzodium/libzodium.zig"),
                    .target = target,
                    .optimize = optimize,
                    .link_libc = true,
                }),
            });
        };
        b.installArtifact(libzodium);
        minisign.root_module.addCMacro("LIBZODIUM", "1");
        minisign.root_module.linkLibrary(libzodium);
    } else {
        var override_pkgconfig = false;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        if (std.process.getEnvVarOwned(allocator, "LIBSODIUM_INCLUDE_PATH")) |path| {
            minisign.root_module.addSystemIncludePath(.{ .cwd_relative = path });
            allocator.free(path);
            override_pkgconfig = true;
        } else |_| {}
        if (std.process.getEnvVarOwned(allocator, "LIBSODIUM_LIB_PATH")) |path| {
            minisign.root_module.addLibraryPath(.{ .cwd_relative = path });
            allocator.free(path);
            override_pkgconfig = true;
        } else |_| {}

        for ([_][]const u8{ "/opt/homebrew/include", "/home/linuxbrew/.linuxbrew/include", "/usr/local/include" }) |path| {
            std.fs.accessAbsolute(path, .{}) catch continue;
            minisign.root_module.addSystemIncludePath(.{ .cwd_relative = path });
        }
        for ([_][]const u8{ "/opt/homebrew/lib", "/home/linuxbrew/.linuxbrew/lib", "/usr/local/lib" }) |path| {
            std.fs.accessAbsolute(path, .{}) catch continue;
            minisign.root_module.addLibraryPath(.{ .cwd_relative = path });
        }
        if (!use_static_linking) {
            minisign.headerpad_max_install_names = true; // required to compile using Homebrew, see https://github.com/jedisct1/minisign/pull/155
        }
        minisign.root_module.linkSystemLibrary(
            "sodium",
            .{
                .use_pkg_config = if (override_pkgconfig) .no else .yes,
                .preferred_link_mode = if (use_static_linking) .static else .dynamic,
            },
        );
    }
    minisign.root_module.addIncludePath(b.path("src"));

    minisign.root_module.addCMacro("_GNU_SOURCE", "1");
    const source_files = &.{ "src/base64.c", "src/get_line.c", "src/helpers.c", "src/minisign.c" };
    minisign.root_module.addCSourceFiles(.{ .files = source_files });

    b.installArtifact(minisign);
}
