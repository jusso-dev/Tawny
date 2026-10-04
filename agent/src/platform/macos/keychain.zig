//! Minimal Security.framework binding for generic-password items in the
//! file-based macOS keychain.
//!
//! Loading: Security.framework and CoreFoundation are opened with dlopen at
//! first use instead of being linked. Release builds of the macOS agent are
//! cross-compiled on Linux without an Apple SDK, so linking frameworks is not
//! possible there; both frameworks live in the dyld shared cache on every
//! supported macOS release.
//!
//! Keychain choice: the data-protection keychain needs a
//! `keychain-access-groups` entitlement and therefore a real code signature.
//! The agent ships ad-hoc signed, so only file-based keychains are usable:
//! `/Library/Keychains/System.keychain` for the root LaunchDaemon, the login
//! keychain for a per-user LaunchAgent.
//!
//! No UI: every call runs with `SecKeychainSetUserInteractionAllowed(false)`,
//! so anything that would prompt (locked keychain, untrusted caller) fails
//! with errSecInteractionNotAllowed / errSecAuthFailed instead of blocking.
//!
//! Access control: since macOS 10.12 every item gets a `partition_id` ACL entry
//! naming the creating binary's partition. For an ad-hoc signed binary that is
//! `cdhash:<hash>`, so only the exact agent build that wrote an item can read
//! it back without a prompt (verified on the login keychain with two builds).
//! The item's application ACL is opened to any application on top of that.
//! This grants no extra reads (the partition check still applies), but lets a
//! later agent build, or `security delete-generic-password`, overwrite or
//! delete an item an older build created. Without it a stale item could be
//! neither read nor replaced. Upgrades therefore export credentials with the
//! old binary first (`--export-credentials`, see install.sh).

const std = @import("std");

pub const OSStatus = i32;
const Boolean = u8;
const CFIndex = isize;
const CFTypeRef = *const anyopaque;
const CFAllocatorRef = ?*const anyopaque;
const OpaquePtr = ?*const anyopaque;

pub const errSecSuccess: OSStatus = 0;
pub const errSecParam: OSStatus = -50;
pub const errSecWrPerm: OSStatus = -61;
pub const errSecUserCanceled: OSStatus = -128;
pub const errSecInvalidOwnerEdit: OSStatus = -25244;
pub const errSecNotAvailable: OSStatus = -25291;
pub const errSecReadOnly: OSStatus = -25292;
pub const errSecAuthFailed: OSStatus = -25293;
pub const errSecNoSuchKeychain: OSStatus = -25294;
pub const errSecDuplicateItem: OSStatus = -25299;
pub const errSecItemNotFound: OSStatus = -25300;
pub const errSecNoDefaultKeychain: OSStatus = -25307;
pub const errSecInteractionNotAllowed: OSStatus = -25308;
pub const errSecMissingEntitlement: OSStatus = -34018;

const kCFStringEncodingUTF8: u32 = 0x08000100;

const CFRange = extern struct { location: CFIndex, length: CFIndex };

/// Function pointers resolved from the frameworks. Field names are the C
/// symbol names.
const Fns = struct {
    CFRelease: *const fn (CFTypeRef) callconv(.c) void,
    CFGetTypeID: *const fn (CFTypeRef) callconv(.c) usize,
    CFDataGetTypeID: *const fn () callconv(.c) usize,
    CFStringCreateWithBytes: *const fn (CFAllocatorRef, [*]const u8, CFIndex, u32, Boolean) callconv(.c) ?CFTypeRef,
    CFDataCreate: *const fn (CFAllocatorRef, [*]const u8, CFIndex) callconv(.c) ?CFTypeRef,
    CFDataGetLength: *const fn (CFTypeRef) callconv(.c) CFIndex,
    CFDataGetBytePtr: *const fn (CFTypeRef) callconv(.c) ?[*]const u8,
    CFDictionaryCreate: *const fn (CFAllocatorRef, [*]const OpaquePtr, [*]const OpaquePtr, CFIndex, *const anyopaque, *const anyopaque) callconv(.c) ?CFTypeRef,
    CFArrayCreate: *const fn (CFAllocatorRef, [*]const OpaquePtr, CFIndex, *const anyopaque) callconv(.c) ?CFTypeRef,
    CFArrayGetCount: *const fn (CFTypeRef) callconv(.c) CFIndex,
    CFArrayGetValueAtIndex: *const fn (CFTypeRef, CFIndex) callconv(.c) OpaquePtr,
    CFArrayContainsValue: *const fn (CFTypeRef, CFRange, OpaquePtr) callconv(.c) Boolean,

    SecItemAdd: *const fn (CFTypeRef, ?*?CFTypeRef) callconv(.c) OSStatus,
    SecItemCopyMatching: *const fn (CFTypeRef, ?*?CFTypeRef) callconv(.c) OSStatus,
    SecItemUpdate: *const fn (CFTypeRef, CFTypeRef) callconv(.c) OSStatus,
    SecItemDelete: *const fn (CFTypeRef) callconv(.c) OSStatus,
    SecKeychainOpen: *const fn ([*:0]const u8, *?CFTypeRef) callconv(.c) OSStatus,
    SecKeychainSetUserInteractionAllowed: *const fn (Boolean) callconv(.c) OSStatus,
    SecAccessCreate: *const fn (CFTypeRef, ?CFTypeRef, *?CFTypeRef) callconv(.c) OSStatus,
    SecAccessCopyACLList: *const fn (CFTypeRef, *?CFTypeRef) callconv(.c) OSStatus,
    SecACLCopyAuthorizations: *const fn (CFTypeRef) callconv(.c) ?CFTypeRef,
    SecACLCopyContents: *const fn (CFTypeRef, *?CFTypeRef, *?CFTypeRef, *u16) callconv(.c) OSStatus,
    SecACLSetContents: *const fn (CFTypeRef, ?CFTypeRef, CFTypeRef, u16) callconv(.c) OSStatus,
};

/// Addresses of exported data symbols. CFStringRef constants are variables
/// holding the string object, so these point at the variable.
const Consts = struct {
    kCFTypeDictionaryKeyCallBacks: *const anyopaque,
    kCFTypeDictionaryValueCallBacks: *const anyopaque,
    kCFTypeArrayCallBacks: *const anyopaque,
    kCFBooleanTrue: *const CFTypeRef,
    kCFBooleanFalse: *const CFTypeRef,
    kSecClass: *const CFTypeRef,
    kSecClassGenericPassword: *const CFTypeRef,
    kSecAttrService: *const CFTypeRef,
    kSecAttrAccount: *const CFTypeRef,
    kSecAttrLabel: *const CFTypeRef,
    kSecAttrAccess: *const CFTypeRef,
    kSecAttrAccessible: *const CFTypeRef,
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: *const CFTypeRef,
    kSecAttrSynchronizable: *const CFTypeRef,
    kSecValueData: *const CFTypeRef,
    kSecReturnData: *const CFTypeRef,
    kSecMatchLimit: *const CFTypeRef,
    kSecMatchLimitOne: *const CFTypeRef,
    kSecMatchSearchList: *const CFTypeRef,
    kSecUseKeychain: *const CFTypeRef,
    kSecACLAuthorizationChangeACL: *const CFTypeRef,
};

const Api = struct {
    f: Fns,
    c: Consts,
};

const security_path = "/System/Library/Frameworks/Security.framework/Security";
const corefoundation_path = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

var api_storage: Api = undefined;
var api_state = std.atomic.Value(u8).init(0); // 0 = not loaded, 1 = ready, 2 = failed

fn api() Error!*const Api {
    switch (api_state.load(.acquire)) {
        1 => return &api_storage,
        2 => return error.KeychainUnavailable,
        else => {},
    }
    loadApi(&api_storage) catch {
        api_state.store(2, .release);
        return error.KeychainUnavailable;
    };
    // Never prompt: a LaunchDaemon has no UI and a LaunchAgent must not nag.
    _ = api_storage.f.SecKeychainSetUserInteractionAllowed(0);
    api_state.store(1, .release);
    return &api_storage;
}

fn loadApi(out: *Api) !void {
    // The libraries stay loaded for the life of the process.
    var cf = try std.DynLib.open(corefoundation_path);
    var sec = try std.DynLib.open(security_path);
    inline for (@typeInfo(Fns).@"struct".field_names, @typeInfo(Fns).@"struct".field_types) |name, T| {
        @field(out.f, name) = sec.lookup(T, name) orelse cf.lookup(T, name) orelse return error.MissingSymbol;
    }
    inline for (@typeInfo(Consts).@"struct".field_names, @typeInfo(Consts).@"struct".field_types) |name, T| {
        @field(out.c, name) = sec.lookup(T, name) orelse cf.lookup(T, name) orelse return error.MissingSymbol;
    }
}

pub const system_keychain_path = "/Library/Keychains/System.keychain";

/// Which file-based keychain to use.
pub const Location = enum {
    /// `/Library/Keychains/System.keychain` (root LaunchDaemon).
    system,
    /// The caller's default keychain, normally the login keychain (LaunchAgent).
    user,
};

pub const Error = error{
    /// The keychain is locked, or the item belongs to another binary and
    /// reading it would need a prompt; no UI is available.
    InteractionNotAllowed,
    /// The framework, keychain or write permission is missing.
    KeychainUnavailable,
    /// Any other Security.framework failure (see `last_status`).
    KeychainFailure,
    OutOfMemory,
};

/// OSStatus from the most recent failing call, for diagnostics.
pub threadlocal var last_status: OSStatus = 0;

fn mapStatus(status: OSStatus) Error {
    last_status = status;
    return switch (status) {
        errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled => error.InteractionNotAllowed,
        errSecNoSuchKeychain,
        errSecNoDefaultKeychain,
        errSecNotAvailable,
        errSecReadOnly,
        errSecWrPerm,
        errSecMissingEntitlement,
        errSecInvalidOwnerEdit,
        => error.KeychainUnavailable,
        else => error.KeychainFailure,
    };
}

fn cfString(a: *const Api, s: []const u8) Error!CFTypeRef {
    return a.f.CFStringCreateWithBytes(null, s.ptr, @intCast(s.len), kCFStringEncodingUTF8, 0) orelse error.OutOfMemory;
}

fn cfData(a: *const Api, bytes: []const u8) Error!CFTypeRef {
    const ptr: [*]const u8 = if (bytes.len == 0) "" else bytes.ptr;
    return a.f.CFDataCreate(null, ptr, @intCast(bytes.len)) orelse error.OutOfMemory;
}

const max_pairs = 12;

/// Small CFDictionary builder. Values added with `putOwned` are released in
/// `deinit`; constants are borrowed.
const Dict = struct {
    a: *const Api,
    keys: [max_pairs]OpaquePtr = undefined,
    values: [max_pairs]OpaquePtr = undefined,
    len: usize = 0,
    owned: [max_pairs]CFTypeRef = undefined,
    owned_len: usize = 0,

    fn put(self: *Dict, key: *const CFTypeRef, value: CFTypeRef) void {
        std.debug.assert(self.len < max_pairs);
        self.keys[self.len] = key.*;
        self.values[self.len] = value;
        self.len += 1;
    }

    fn putOwned(self: *Dict, key: *const CFTypeRef, value: CFTypeRef) void {
        self.owned[self.owned_len] = value;
        self.owned_len += 1;
        self.put(key, value);
    }

    fn create(self: *const Dict) Error!CFTypeRef {
        return self.a.f.CFDictionaryCreate(
            null,
            &self.keys,
            &self.values,
            @intCast(self.len),
            self.a.c.kCFTypeDictionaryKeyCallBacks,
            self.a.c.kCFTypeDictionaryValueCallBacks,
        ) orelse error.OutOfMemory;
    }

    fn deinit(self: *Dict) void {
        for (self.owned[0..self.owned_len]) |v| self.a.f.CFRelease(v);
        self.owned_len = 0;
    }
};

fn openSystemKeychain(a: *const Api) Error!CFTypeRef {
    var kc: ?CFTypeRef = null;
    const status = a.f.SecKeychainOpen(system_keychain_path, &kc);
    if (status != errSecSuccess) return mapStatus(status);
    return kc orelse mapStatus(errSecNoSuchKeychain);
}

/// class + service + account, scoped to one keychain. For `.system` the
/// search list is pinned to System.keychain so a root process never reads or
/// writes a same-named item in another keychain.
fn baseQuery(d: *Dict, location: Location, service: []const u8, account: []const u8) Error!void {
    const a = d.a;
    d.put(a.c.kSecClass, a.c.kSecClassGenericPassword.*);
    d.putOwned(a.c.kSecAttrService, try cfString(a, service));
    d.putOwned(a.c.kSecAttrAccount, try cfString(a, account));
    if (location == .system) {
        const kc = try openSystemKeychain(a);
        defer a.f.CFRelease(kc);
        var values = [_]OpaquePtr{kc};
        const list = a.f.CFArrayCreate(null, &values, 1, a.c.kCFTypeArrayCallBacks) orelse return error.OutOfMemory;
        d.putOwned(a.c.kSecMatchSearchList, list);
    }
}

/// Return the secret bytes, or null when no such item exists.
pub fn get(alloc: std.mem.Allocator, location: Location, service: []const u8, account: []const u8) Error!?[]u8 {
    const a = try api();
    var q: Dict = .{ .a = a };
    defer q.deinit();
    try baseQuery(&q, location, service, account);
    q.put(a.c.kSecReturnData, a.c.kCFBooleanTrue.*);
    q.put(a.c.kSecMatchLimit, a.c.kSecMatchLimitOne.*);
    const query = try q.create();
    defer a.f.CFRelease(query);

    var result: ?CFTypeRef = null;
    const status = a.f.SecItemCopyMatching(query, &result);
    if (status == errSecItemNotFound) return null;
    if (status != errSecSuccess) return mapStatus(status);
    const data = result orelse return mapStatus(errSecItemNotFound);
    defer a.f.CFRelease(data);
    if (a.f.CFGetTypeID(data) != a.f.CFDataGetTypeID()) return mapStatus(errSecParam);

    const len: usize = @intCast(a.f.CFDataGetLength(data));
    const out = try alloc.alloc(u8, len);
    if (len > 0) @memcpy(out, a.f.CFDataGetBytePtr(data).?[0..len]);
    return out;
}

fn update(a: *const Api, location: Location, service: []const u8, account: []const u8, data: CFTypeRef) Error!OSStatus {
    var q: Dict = .{ .a = a };
    defer q.deinit();
    try baseQuery(&q, location, service, account);
    const query = try q.create();
    defer a.f.CFRelease(query);
    var u: Dict = .{ .a = a };
    u.put(a.c.kSecValueData, data);
    const attrs = try u.create();
    defer a.f.CFRelease(attrs);
    return a.f.SecItemUpdate(query, attrs);
}

/// Create or replace the secret. An existing item is updated in place, so the
/// secret is never absent between a delete and an add.
pub fn put(location: Location, service: []const u8, account: []const u8, secret: []const u8) Error!void {
    const a = try api();
    const data = try cfData(a, secret);
    defer a.f.CFRelease(data);

    const updated = try update(a, location, service, account, data);
    if (updated == errSecSuccess) return;
    if (updated != errSecItemNotFound) return mapStatus(updated);

    var d: Dict = .{ .a = a };
    defer d.deinit();
    d.put(a.c.kSecClass, a.c.kSecClassGenericPassword.*);
    d.putOwned(a.c.kSecAttrService, try cfString(a, service));
    d.putOwned(a.c.kSecAttrAccount, try cfString(a, account));
    d.putOwned(a.c.kSecAttrLabel, try cfString(a, service));
    d.put(a.c.kSecValueData, data);
    // Never synced to iCloud. kSecAttrAccessible only applies to the
    // data-protection keychain; file-based keychains accept and ignore it.
    d.put(a.c.kSecAttrSynchronizable, a.c.kCFBooleanFalse.*);
    d.put(a.c.kSecAttrAccessible, a.c.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.*);
    d.putOwned(a.c.kSecAttrAccess, try openAccess(a, service));
    if (location == .system) d.putOwned(a.c.kSecUseKeychain, try openSystemKeychain(a));
    const attrs = try d.create();
    defer a.f.CFRelease(attrs);

    const status = a.f.SecItemAdd(attrs, null);
    if (status == errSecSuccess) return;
    if (status == errSecDuplicateItem) {
        // Lost a race with another writer: update once more.
        const retry = try update(a, location, service, account, data);
        if (retry == errSecSuccess) return;
        return mapStatus(retry);
    }
    return mapStatus(status);
}

/// Remove the secret. A missing item is not an error.
pub fn delete(location: Location, service: []const u8, account: []const u8) Error!void {
    const a = try api();
    var q: Dict = .{ .a = a };
    defer q.deinit();
    try baseQuery(&q, location, service, account);
    const query = try q.create();
    defer a.f.CFRelease(query);
    const status = a.f.SecItemDelete(query);
    if (status == errSecSuccess or status == errSecItemNotFound) return;
    return mapStatus(status);
}

/// SecAccess whose application lists (except change-ACL) are "any
/// application". Reads stay limited to the creating binary by the partition
/// list the keychain adds on creation; see the file comment.
fn openAccess(a: *const Api, descriptor: []const u8) Error!CFTypeRef {
    const desc = try cfString(a, descriptor);
    defer a.f.CFRelease(desc);
    var access: ?CFTypeRef = null;
    var status = a.f.SecAccessCreate(desc, null, &access);
    if (status != errSecSuccess) return mapStatus(status);
    const acc = access orelse return mapStatus(errSecParam);
    errdefer a.f.CFRelease(acc);

    var list: ?CFTypeRef = null;
    status = a.f.SecAccessCopyACLList(acc, &list);
    if (status != errSecSuccess) return mapStatus(status);
    const acls = list orelse return mapStatus(errSecParam);
    defer a.f.CFRelease(acls);

    const count = a.f.CFArrayGetCount(acls);
    var i: CFIndex = 0;
    while (i < count) : (i += 1) {
        const acl: CFTypeRef = a.f.CFArrayGetValueAtIndex(acls, i) orelse continue;
        if (a.f.SecACLCopyAuthorizations(acl)) |auths| {
            defer a.f.CFRelease(auths);
            const range = CFRange{ .location = 0, .length = a.f.CFArrayGetCount(auths) };
            if (a.f.CFArrayContainsValue(auths, range, a.c.kSecACLAuthorizationChangeACL.*) != 0) continue;
        }
        var apps: ?CFTypeRef = null;
        var acl_desc: ?CFTypeRef = null;
        var prompt: u16 = 0;
        status = a.f.SecACLCopyContents(acl, &apps, &acl_desc, &prompt);
        if (status != errSecSuccess) return mapStatus(status);
        defer if (apps) |v| a.f.CFRelease(v);
        defer if (acl_desc) |v| a.f.CFRelease(v);
        status = a.f.SecACLSetContents(acl, null, acl_desc orelse desc, prompt);
        if (status != errSecSuccess) return mapStatus(status);
    }
    return acc;
}
