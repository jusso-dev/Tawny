const std = @import("std");

pub const GetEnvVarError = error{
    EnvironmentVariableNotFound,
    OutOfMemory,
};

pub fn getEnvVarOwned(allocator: std.mem.Allocator, name: [:0]const u8) GetEnvVarError![]u8 {
    const value = std.c.getenv(name.ptr) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, std.mem.span(value));
}
