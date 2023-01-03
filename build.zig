const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    var target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const minisign = b.addExecutable("minisign", null);
    minisign.setTarget(target);
    minisign.setBuildMode(mode);
    minisign.install();
    minisign.linkLibC();
    minisign.addLibraryPath("/opt/homebrew/lib");
    minisign.addLibraryPath("/usr/local/lib");
    minisign.linkSystemLibrary("sodium");

    minisign.addIncludePath("src");
    minisign.addSystemIncludePath("/opt/homebrew/include");
    minisign.addSystemIncludePath("/usr/local/include");
    minisign.defineCMacro("_GNU_SOURCE", "1");
    minisign.addCSourceFiles(&.{ "src/base64.c", "src/get_line.c", "src/helpers.c", "src/minisign.c" }, &.{});
}
