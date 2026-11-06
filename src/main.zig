//! rex-paste helper binary. The Mac runs the clipboard, prepare, send, and serve commands;
//! every host runs push, lookup, and discard to receive transfers.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = std.Io.Dir;
const File = std.Io.File;
const posix = std.posix;

const gpa = std.heap.smp_allocator;
const is_mac = builtin.target.os.tag == .macos;
const source_limit = 256 * 1024 * 1024;
const chunk_size = 45056; // Base64 chunk plus JSON stays under Rex's 64KiB request limit.
const receive_action = "rex_paste_receive";
// Each request to the host. Over a congested tunnel the slowest of 1080 parallel 45 KB requests
// took 0.84s, while a stalled connection stays silent; Worker.run replaces one that times out.
const request_timeout_s = 10;
const png_signature = "\x89PNG\r\n\x1a\n";
const no_path = @as(?[]const u8, null);

// Settings come from the Lua setup{} options as REX_PASTE_* environment variables.
const Config = struct {
    max_size: usize = 16 * 1024 * 1024, // one limit for prepared images and regular files
    resize: bool = true,
    max_dimension: u32 = 2000,
    compress: bool = true, // lossless WebP; false keeps the original format
    connections: usize = 12,
};
var config: Config = .{};

fn envInt(env: *const std.process.Environ.Map, comptime T: type, name: []const u8, min: T, max: T) !?T {
    const value = env.get(name) orelse return null;
    const n = std.fmt.parseInt(T, value, 10) catch return error.InvalidSetting;
    if (n < min or n > max) return error.InvalidSetting;
    return n;
}

fn loadConfig(env: *const std.process.Environ.Map) !void {
    if (try envInt(env, usize, "REX_PASTE_MAX_SIZE", 1, std.math.maxInt(u32))) |v| config.max_size = v;
    if (try envInt(env, u1, "REX_PASTE_RESIZE", 0, 1)) |v| config.resize = v == 1;
    if (try envInt(env, u32, "REX_PASTE_MAX_DIMENSION", 1, 65535)) |v| config.max_dimension = v;
    if (try envInt(env, u1, "REX_PASTE_COMPRESS", 0, 1)) |v| config.compress = v == 1;
    if (try envInt(env, usize, "REX_PASTE_CONNECTIONS", 1, std.math.maxInt(u16))) |v| config.connections = v;
}

// macOS only: src/mac.m and src/codec.c.
extern fn clipboard_read(board: ?[*:0]const u8, out: *?[*]u8, len: *usize) c_int;
extern fn encode_image(data: [*]const u8, len: usize, out: *?[*]u8, out_len: *usize, as_png: c_int) c_int;
extern fn encode_same_format(data: [*]const u8, len: usize, out: *?[*]u8, out_len: *usize) c_int;
extern fn image_supported(data: [*]const u8, len: usize) c_int;
extern fn image_dimensions(data: [*]const u8, len: usize, width: *c_uint, height: *c_uint) c_int;
extern var rex_max_dimension: c_int;

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn digest(data: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return hash;
}

fn sha256Hex(data: []const u8) [64]u8 {
    return std.fmt.bytesToHex(digest(data), .lower);
}

fn randomId(io: Io) ![32]u8 {
    var bytes: [16]u8 = undefined;
    try io.randomSecure(&bytes);
    return std.fmt.bytesToHex(bytes, .lower);
}

fn validHex(value: []const u8, len: usize) !void {
    if (value.len != len) return error.InvalidToken;
    for (value) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return error.InvalidToken,
    };
}

fn validName(name: []const u8) !void {
    if (name.len == 0 or name.len > 255 or eq(name, ".") or eq(name, "..")) return error.InvalidFileName;
    for (name) |c| if (c == '/' or c < 0x20 or c == 0x7f) return error.InvalidFileName;
}

fn output(io: Io, value: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var stdout = File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(value, .{}, &stdout.interface);
    try stdout.interface.writeByte('\n');
    try stdout.interface.flush();
}

/// Reads the rest of `reader`; error.StreamTooLong if it holds more than `max` bytes.
fn readAll(reader: *File.Reader, max: usize) ![]u8 {
    return reader.interface.allocRemaining(gpa, .limited(max + 1)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => |e| return e,
    };
}

fn readFile(io: Io, file: File, max: usize) ![]u8 {
    var reader = file.reader(io, &.{});
    return readAll(&reader, max);
}

// Io.File.Stat has no owner and Io creates files through symlinks, so cache entries are opened
// with openat(2) and O_NOFOLLOW and checked with fstat(2), or statx(2) on Linux.
const FdStat = struct { uid: posix.uid_t, nlink: u64, mode: u32 };

fn ownedStat(fd: posix.fd_t) !FdStat {
    const stat: FdStat = if (builtin.target.os.tag == .linux) linux: {
        const linux = std.os.linux;
        var statx: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .NLINK = true, .UID = true }, &statx)) != .SUCCESS)
            return error.StatFailed;
        break :linux .{ .uid = statx.uid, .nlink = statx.nlink, .mode = statx.mode };
    } else other: {
        var buf: std.c.Stat = undefined;
        if (std.c.fstat(fd, &buf) != 0) return error.StatFailed;
        break :other .{ .uid = buf.uid, .nlink = buf.nlink, .mode = buf.mode };
    };
    if (stat.uid != std.c.getuid()) return error.InvalidStagingOwner;
    return stat;
}

/// Sets an entry's mtime to now. cleanup removes entries unused for a day, so every use of a
/// cache entry, such as pasting its path again, renews it.
fn touchFd(fd: posix.fd_t) !void {
    if (std.c.futimens(fd, null) != 0) return error.TouchFailed;
}

// Images the receiver stores and pastes, recognized by signature on every platform.
const image_extensions = .{ ".webp", ".png", ".jpg", ".tiff", ".gif", ".heic", ".avif", ".image" };

fn extension(data: []const u8) ![]const u8 {
    if (data.len == 0 or data.len > source_limit) return error.InvalidImageSize;
    const startsWith = std.mem.startsWith;
    if (startsWith(u8, data, png_signature)) return ".png";
    if (data.len >= 12 and eq(data[0..4], "RIFF") and eq(data[8..12], "WEBP")) return ".webp";
    if (startsWith(u8, data, "\xff\xd8\xff")) return ".jpg";
    if (startsWith(u8, data, "II*\x00") or startsWith(u8, data, "MM\x00*")) return ".tiff";
    if (startsWith(u8, data, "GIF87a") or startsWith(u8, data, "GIF89a")) return ".gif";
    if (data.len >= 12 and eq(data[4..8], "ftyp")) {
        const brand = data[8..12];
        if (eq(brand, "avif") or eq(brand, "avis")) return ".avif";
        inline for (.{ "heic", "heix", "hevc", "hevx", "heim", "heis", "mif1", "msf1" }) |b|
            if (eq(brand, b)) return ".heic";
    }
    // Other formats ImageIO can read are kept locally only; the Linux receiver rejects them.
    if (is_mac and image_supported(data.ptr, data.len) != 0) return ".image";
    return error.InvalidImage;
}

/// The private cache directory, ~/.cache/rex-paste/v2. Entries are owner-only and never followed through symlinks.
const Store = struct {
    io: Io,
    dir: Dir,
    path: []const u8,

    fn init(io: Io, home: []const u8) !Store {
        const path = try std.fs.path.join(gpa, &.{ home, ".cache", "rex-paste", "v2" });
        try Dir.cwd().createDirPath(io, path);
        return open(io, Dir.cwd(), path);
    }

    fn open(io: Io, parent: Dir, path: []const u8) !Store {
        const dir = try parent.openDir(io, path, .{ .iterate = true, .follow_symlinks = false });
        errdefer dir.close(io);
        _ = try ownedStat(dir.handle);
        try dir.setPermissions(io, .fromMode(0o700));
        return .{ .io = io, .dir = dir, .path = path };
    }

    fn close(self: Store) void {
        self.dir.close(self.io);
    }

    fn openFile(self: Store, name: []const u8, write: bool, create: bool) !File {
        // macOS fails some open(O_CREAT) calls with ENOENT while other processes create the
        // same name, as the first chunks of a transfer do. O_EXCL creates atomically, and a
        // name that already exists is opened without O_CREAT.
        const fd = if (create) self.openAt(name, write, true) catch |err| switch (err) {
            error.PathAlreadyExists => try self.openAt(name, write, false),
            else => return err,
        } else try self.openAt(name, write, false);
        const file: File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
        errdefer file.close(self.io);
        const stat = try ownedStat(fd);
        if (stat.mode & posix.S.IFMT != posix.S.IFREG or stat.nlink != 1) return error.InvalidStagingFile;
        return file;
    }

    fn read(self: Store, name: []const u8, max: usize) ![]u8 {
        const file = try self.openFile(name, false, false);
        defer file.close(self.io);
        try touchFd(file.handle);
        return readFile(self.io, file, max);
    }

    /// Marks an existing entry as used, as read does; false when there is none.
    fn touch(self: Store, name: []const u8) !bool {
        const file = self.openFile(name, false, false) catch |err| return if (err == error.FileNotFound) false else err;
        defer file.close(self.io);
        try touchFd(file.handle);
        return true;
    }

    fn save(self: Store, name: []const u8, data: []const u8) !void {
        const id = try randomId(self.io);
        const tmp = try gpa.print("{s}.tmp", .{&id});
        defer gpa.free(tmp);
        const file = try self.dir.createFile(self.io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        errdefer self.dir.deleteFile(self.io, tmp) catch {};
        {
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, data);
        }
        try self.dir.rename(tmp, self.dir, name, self.io);
    }

    fn openAt(self: Store, name: []const u8, write: bool, create: bool) !posix.fd_t {
        return posix.openat(self.dir.handle, name, .{
            .ACCMODE = if (write) .RDWR else .RDONLY,
            .CREAT = create,
            .EXCL = create,
            .NOFOLLOW = true,
            .CLOEXEC = true,
            .NONBLOCK = true, // never block opening a FIFO planted in the cache
        }, 0o600);
    }

    /// Removes cache entries unused for a day: `<hex>.<ext>` files and `<sha256>/` file directories.
    fn cleanup(self: Store) !void {
        const now = Io.Timestamp.now(self.io, .real);
        var it = self.dir.iterate();
        while (try it.next(self.io)) |entry| {
            const stem = switch (entry.kind) {
                .directory => entry.name,
                .file => entry.name[0 .. std.mem.findScalar(u8, entry.name, '.') orelse continue],
                else => continue,
            };
            if (stem.len != 32 and stem.len != 64) continue;
            validHex(stem, stem.len) catch continue;
            const stat = self.dir.statFile(self.io, entry.name, .{ .follow_symlinks = false }) catch continue;
            if (stat.mtime.durationTo(now).nanoseconds < std.time.ns_per_day) continue;
            if (entry.kind == .directory)
                self.dir.deleteTree(self.io, entry.name) catch {}
            else
                self.dir.deleteFile(self.io, entry.name) catch {};
        }
    }
};

const Image = struct { path: []const u8, sha256: [64]u8 };

/// Saves an image as `<sha256>.<ext>`. With `prepare`, it is first resized and compressed per the settings.
fn storeImage(store: Store, original: []const u8, prepare: bool) !Image {
    var data = original;
    const ext = try extension(original);
    // compress=false keeps the format only if receivers recognize it; other formats become WebP.
    const webp = config.compress or eq(ext, ".image");
    if (is_mac and prepare and (webp or try exceedsBound(original))) data = try prepared(store, original, ext, webp);
    if (prepare and data.len > config.max_size) return error.ImageTooLarge;
    const hash = sha256Hex(data);
    const name = try gpa.print("{s}{s}", .{ &hash, try extension(data) });
    if (!try store.touch(name)) try store.save(name, data);
    return .{ .path = try std.fs.path.join(gpa, &.{ store.path, name }), .sha256 = hash };
}

fn exceedsBound(data: []const u8) !bool {
    if (!config.resize) return false;
    var w: c_uint = 0;
    var h: c_uint = 0;
    if (image_dimensions(data.ptr, data.len, &w, &h) == 0) return error.InvalidImage;
    return @max(w, h) > config.max_dimension;
}

/// Resizes and encodes as WebP, or in the source format; results are cached by source hash and settings.
fn prepared(store: Store, original: []const u8, ext: []const u8, webp: bool) ![]const u8 {
    rex_max_dimension = if (config.resize) @intCast(config.max_dimension) else 0;
    const kind = if (webp) "webp" else ext[1..];
    const cache = try gpa.print("{s}.r{d}-{s}-v7.cache", .{ &sha256Hex(original), rex_max_dimension, kind });
    defer gpa.free(cache);
    if (store.read(cache, config.max_size)) |cached| {
        _ = try extension(cached);
        return cached;
    } else |err| switch (err) {
        error.FileNotFound => {},
        error.StreamTooLong => return error.ImageTooLarge, // cached under a larger max_size
        else => return err,
    }
    var ptr: ?[*]u8 = null;
    var len: usize = 0;
    const ok = if (webp or eq(ext, ".webp"))
        encode_image(original.ptr, original.len, &ptr, &len, 0)
    else if (eq(ext, ".png"))
        encode_image(original.ptr, original.len, &ptr, &len, 1)
    else
        encode_same_format(original.ptr, original.len, &ptr, &len);
    if (ok == 0) return error.ImagePreparationFailed;
    defer std.c.free(ptr);
    if (len > config.max_size) return error.ImageTooLarge;
    const data = try gpa.dupe(u8, ptr.?[0..len]);
    try store.save(cache, data);
    return data;
}

fn storedImage(store: Store, sha256: []const u8) ![]u8 {
    try validHex(sha256, 64);
    inline for (image_extensions) |ext| {
        const name = try gpa.print("{s}{s}", .{ sha256, ext });
        defer gpa.free(name);
        if (store.read(name, config.max_size)) |data| {
            if (!eq(&sha256Hex(data), sha256)) return error.HashMismatch;
            _ = try extension(data);
            return data;
        } else |err| if (err != error.FileNotFound) return err;
    }
    return error.FileNotFound;
}

// Regular files live at `<sha256>/<name>` so the original name is kept.
fn fileDir(store: Store, sha256: []const u8, create: bool) !Store {
    if (create) store.dir.createDir(store.io, sha256, .fromMode(0o700)) catch |err|
        if (err != error.PathAlreadyExists) return err;
    var sub = try Store.open(store.io, store.dir, sha256);
    try touchFd(sub.dir.handle); // cleanup judges a file directory by its own mtime
    sub.path = try std.fs.path.join(gpa, &.{ store.path, sha256 });
    return sub;
}

fn storedFile(store: Store, sha256: []const u8, name: []const u8) ![]const u8 {
    const sub = try fileDir(store, sha256, false);
    defer sub.close();
    const data = try sub.read(name, config.max_size);
    defer gpa.free(data);
    if (!eq(&sha256Hex(data), sha256)) return error.HashMismatch;
    return std.fs.path.join(gpa, &.{ sub.path, name });
}

fn imagePath(store: Store, sha256: []const u8, data: []const u8) ![]const u8 {
    return gpa.print("{s}/{s}{s}", .{ store.path, sha256, try extension(data) });
}

/// One chunk of a transfer. `name` is set for regular files and absent for images.
const Push = struct {
    token: []const u8,
    size: usize,
    sha256: []const u8,
    offset: usize,
    data: []const u8,
    name: ?[]const u8 = null,
};

fn cachedPath(store: Store, p: Push) !?[]const u8 {
    if (p.name) |name| {
        if (storedFile(store, p.sha256, name)) |path| return path else |err| return if (err == error.FileNotFound) null else err;
    }
    const cached = storedImage(store, p.sha256) catch |err|
        return if (err == error.FileNotFound) null else err;
    defer gpa.free(cached);
    if (cached.len != p.size) return error.HashMismatch;
    return try imagePath(store, p.sha256, cached);
}

fn chunkCount(size: usize) usize {
    return @divCeil(size, chunk_size);
}

// State file: hash 32 + size 4 + start time 8 (Unix ms) + chunk bitmap + flags 1.
const state_header = 44;
const flag_done = 1;
const flag_progress = 2; // a push already asked for the progress float

fn stateLen(size: usize) usize {
    return state_header + @divCeil(chunkCount(size), 8) + 1;
}

fn setChunk(state: []u8, index: usize) void {
    state[state_header + index / 8] |= @as(u8, 1) << @intCast(index % 8);
}

fn receivedChunks(state: []const u8) usize {
    var n: usize = 0;
    for (state[state_header .. state.len - 1]) |byte| n += @popCount(byte);
    return n;
}

fn nowMs(io: Io) i64 {
    return Io.Timestamp.now(io, .real).toMilliseconds();
}

/// Writes one chunk and prints the path once the file is complete and verified, else null.
/// `done` tells the sender that this host needs no more chunks of the transfer.
/// An incomplete transfer still arriving after a second gets `progress`, the width of its
/// progress line, exactly once.
/// The state file lock makes init, bitmap update, and completion run exactly once.
fn push(store: Store, p: Push) !void {
    const io = store.io;
    try validHex(p.token, 32);
    try validHex(p.sha256, 64);
    if (p.name) |name| try validName(name);
    if (p.size > config.max_size) return error.TransferTooLarge;
    if (p.size == 0 or p.offset >= p.size or p.offset % chunk_size != 0) return error.InvalidChunk;
    const decoder = std.base64.standard.Decoder;
    const len = try decoder.calcSizeForSlice(p.data);
    if (len != @min(chunk_size, p.size - p.offset)) return error.InvalidChunk;
    const bytes = try gpa.alloc(u8, len);
    defer gpa.free(bytes);
    try decoder.decode(bytes, p.data);
    var expected_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_hash, p.sha256);

    const state_name = try gpa.print("{s}.state", .{p.token});
    const part_name = try gpa.print("{s}.part", .{p.token});
    const state_file = try store.openFile(state_name, true, true);
    defer state_file.close(io);
    try state_file.lock(io, .exclusive);
    defer state_file.unlock(io);
    const state = try gpa.alloc(u8, stateLen(p.size));
    defer gpa.free(state);
    @memset(state, 0);
    const state_size = (try state_file.stat(io)).size;
    if (state_size == 0) {
        try store.cleanup();
        @memcpy(state[0..32], &expected_hash);
        std.mem.writeInt(u32, state[32..36], @intCast(p.size), .little);
        std.mem.writeInt(i64, state[36..44], nowMs(io), .little);
        const part = try store.dir.createFile(io, part_name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer part.close(io);
        try part.setLength(io, p.size);
        try state_file.writePositionalAll(io, state, 0);
    } else {
        if (state_size != state.len or try state_file.readPositionalAll(io, state, 0) != state.len) return error.InvalidState;
        if (!eq(state[0..32], &expected_hash) or std.mem.readInt(u32, state[32..36], .little) != p.size)
            return error.TransferConflict;
        if (state[state.len - 1] & flag_done != 0) return output(io, .{ .path = no_path, .done = true });
    }
    // An existing cache entry is still hash-verified. Each transfer returns a paste path only once.
    if (try cachedPath(store, p)) |path| {
        state[state.len - 1] |= flag_done;
        try state_file.writePositionalAll(io, state, 0);
        try store.dir.deleteFile(io, part_name);
        return output(io, .{ .path = path, .done = true });
    }
    const part = try store.openFile(part_name, true, false);
    defer part.close(io);
    if ((try part.stat(io)).size != p.size) return error.InvalidState;
    try part.writePositionalAll(io, bytes, p.offset);
    setChunk(state, p.offset / chunk_size);
    const received = receivedChunks(state) == chunkCount(p.size);
    const show = !received and state[state.len - 1] & flag_progress == 0 and
        nowMs(io) - std.mem.readInt(i64, state[36..44], .little) >= 1000;
    if (show) state[state.len - 1] |= flag_progress;
    try state_file.writePositionalAll(io, state, 0);
    if (!received) return output(io, .{ .path = no_path, .progress = if (show) progressWidth(p.name orelse "image", p.size) else null });

    const complete = try readFile(io, part, config.max_size);
    defer gpa.free(complete);
    if (complete.len != p.size or !eq(&digest(complete), &expected_hash)) return error.HashMismatch;
    const path = if (p.name) |name| file: {
        const sub = try fileDir(store, p.sha256, true);
        defer sub.close();
        try store.dir.rename(part_name, sub.dir, name, io);
        break :file try std.fs.path.join(gpa, &.{ sub.path, name });
    } else image: {
        const path = try imagePath(store, p.sha256, complete);
        try store.dir.rename(part_name, store.dir, std.fs.path.basename(path), io);
        break :image path;
    };
    state[state.len - 1] |= flag_done;
    try state_file.writePositionalAll(io, state, 0);
    try output(io, .{ .path = path, .done = true });
}

/// Draws the progress of transfer `token` as this host receives it, after `label`, until the
/// transfer completes, is discarded, or makes no progress for 30 seconds. Runs in a float.
fn progress(store: Store, token: []const u8, label: []const u8) !void {
    const io = store.io;
    try validHex(token, 32);
    const state_name = try gpa.print("{s}.state", .{token});
    const stdout = File.stdout();
    try stdout.writeStreamingAll(io, "\x1b[?25l"); // hide the cursor
    var shown: ?usize = null;
    var idle: usize = 0;
    while (idle < 300) : (idle += 1) {
        const file = store.openFile(state_name, false, false) catch |err| switch (err) {
            // Not started yet, or discarded after a failure.
            error.FileNotFound => if (shown == null) {
                try io.sleep(.fromMilliseconds(100), .awake);
                continue;
            } else return,
            else => return err,
        };
        defer file.close(io);
        defer io.sleep(.fromMilliseconds(100), .awake) catch {};
        var header: [state_header]u8 = undefined;
        if (try file.readPositionalAll(io, &header, 0) != header.len) continue;
        const size: usize = std.mem.readInt(u32, header[32..36], .little);
        if (size == 0) return error.InvalidState;
        const state = try gpa.alloc(u8, stateLen(size));
        defer gpa.free(state);
        if (try file.readPositionalAll(io, state, 0) != state.len) continue;
        const done = state[state.len - 1] & flag_done != 0;
        const bytes = if (done) size else @min(size, receivedChunks(state) * chunk_size);
        // The last chunk shows 100% before the file is verified, so done can arrive alone.
        if (shown == bytes and !done) continue;
        shown = bytes;
        idle = 0;
        try drawProgress(io, stdout, label, bytes, size);
        if (done) return io.sleep(.fromMilliseconds(500), .awake); // let 100% show before the float closes
    }
}

/// Columns of drawProgress's line at its widest, plus two spare.
fn progressWidth(label: []const u8, size: usize) usize {
    var buf: [32]u8 = undefined;
    const mib = std.fmt.bufPrint(&buf, "{d:.1}", .{@as(f64, @floatFromInt(size)) / (1024.0 * 1024.0)}) catch unreachable;
    return label.len + 38 + 2 * mib.len;
}

/// One line: label, a bar of blocks that fills in eighths of a cell, percent, and MiB.
fn drawProgress(io: Io, stdout: File, label: []const u8, bytes: usize, size: usize) !void {
    const cells = 20;
    const eighths = cells * 8 * bytes / size;
    const partial = [_][]const u8{ "", "▏", "▎", "▍", "▌", "▋", "▊", "▉" };
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("\r{s}  \x1b[36m", .{label});
    for (0..eighths / 8) |_| try w.writeAll("█");
    try w.writeAll(partial[eighths % 8]);
    try w.writeAll("\x1b[90m");
    for (0..cells - @divCeil(eighths, 8)) |_| try w.writeAll("░");
    const mib = 1024.0 * 1024.0;
    try w.print("\x1b[0m {d:>3}%  {d:.1} / {d:.1} MiB", .{
        100 * bytes / size, @as(f64, @floatFromInt(bytes)) / mib, @as(f64, @floatFromInt(size)) / mib,
    });
    try stdout.writeStreamingAll(io, w.buffered());
}

/// A request to the sender pool, one JSON line. Images send `token` (the prepared image hash);
/// regular files send `path`.
const PoolRequest = struct {
    token: ?[]const u8 = null,
    path: ?[]const u8 = null,
    session_id: []const u8,
    block_id: []const u8,
    transfer_id: []const u8,
};

// Bytes to send: images come from the verified cache, regular files from their original path.
const Payload = struct {
    data: []u8,
    sha256: [64]u8,
    name: ?[]const u8 = null,

    fn read(store: Store, request: PoolRequest) !Payload {
        if (request.path) |path| {
            const data = readPath(store.io, path, config.max_size) catch |err|
                return if (err == error.StreamTooLong) error.FileTooLarge else err;
            if (data.len == 0) return error.EmptyFile;
            return .{ .data = data, .sha256 = sha256Hex(data), .name = std.fs.path.basename(path) };
        }
        const token = request.token orelse return error.InvalidRequest;
        const data = try storedImage(store, token);
        return .{ .data = data, .sha256 = token[0..64].* };
    }

    fn chunk(self: *const Payload, allocator: std.mem.Allocator, offset: usize, request: PoolRequest) ![]u8 {
        const bytes = self.data[offset..@min(self.data.len, offset + chunk_size)];
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(bytes.len));
        const json = try std.json.Stringify.valueAlloc(allocator, .{
            .action = receive_action,
            .args = .{
                .op = "push",
                .token = request.transfer_id,
                .size = self.data.len,
                .sha256 = self.sha256[0..],
                .offset = offset,
                .data = encoder.encode(encoded, bytes),
                .session_id = request.session_id,
                .block_id = request.block_id,
                .name = self.name,
            },
        }, .{ .emit_null_optional_fields = false });
        if (json.len >= 65536) return error.ControlMessageTooLarge;
        return json;
    }
};

// Worker pipes use poll(2) with deadlines so a stalled connection fails instead of hanging the pool.
fn deadlineAfter(io: Io, timeout_ms: u64) Io.Timestamp {
    return Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(@intCast(timeout_ms)));
}

fn waitFd(io: Io, fd: posix.fd_t, events: i16, deadline: Io.Timestamp) !void {
    const left = Io.Timestamp.now(io, .awake).durationTo(deadline).toMilliseconds();
    if (left <= 0) return error.WorkerTimeout;
    var polls = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    if (try posix.poll(&polls, @intCast(@min(left, std.math.maxInt(i32)))) == 0) return error.WorkerTimeout;
}

fn readLine(io: Io, fd: posix.fd_t, buf: []u8, timeout_ms: u64) ![]const u8 {
    const deadline = deadlineAfter(io, timeout_ms);
    for (0..buf.len) |n| {
        try waitFd(io, fd, posix.POLL.IN, deadline);
        if (try posix.read(fd, buf[n .. n + 1]) != 1) return error.WorkerClosed;
        if (buf[n] == '\n') return buf[0..n];
    }
    return error.WorkerResponseTooLong;
}

fn writeAll(io: Io, fd: posix.fd_t, data: []const u8, deadline: Io.Timestamp) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        try waitFd(io, fd, posix.POLL.OUT, deadline);
        const rc = std.c.write(fd, data[offset..].ptr, data.len - offset);
        if (rc < 0) switch (std.c.errno(rc)) {
            .AGAIN, .INTR => continue,
            else => return error.WorkerClosed,
        };
        if (rc == 0) return error.WorkerClosed;
        offset += @intCast(rc);
    }
}

/// One `rex do worker.lua` process holding a connection to the remote host. Each input frame
/// is an 8-digit hex length followed by one client.action request, and gets one reply line.
const Worker = struct {
    io: Io,
    argv: []const []const u8,
    child: ?std.process.Child = null,

    fn start(self: *Worker) void {
        self.open() catch {};
    }

    fn open(self: *Worker) !void {
        self.child = try std.process.spawn(self.io, .{
            .argv = self.argv,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
        });
        errdefer self.stop();
        // Writes to the worker are non-blocking so their deadline holds.
        const stdin = self.child.?.stdin.?.handle;
        const flags = std.c.fcntl(stdin, std.c.F.GETFL);
        const nonblock: c_int = @bitCast(@as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
        if (flags < 0 or std.c.fcntl(stdin, std.c.F.SETFL, flags | nonblock) < 0) return error.WorkerPipeFailed;
        var buffer: [512]u8 = undefined;
        if (!eq(try readLine(self.io, self.child.?.stdout.?.handle, &buffer, 15000), "READY")) return error.WorkerNotReady;
    }

    /// Sends the queue's chunks one at a time until none are left. A failed connection gives
    /// its chunk back to the queue and is replaced.
    fn run(self: *Worker, queue: *Queue) void {
        if (self.child == null) self.open() catch |err| return queue.note(@errorName(err));
        while (queue.take()) |i| {
            const done = self.send(queue, queue.lines[i]) catch |err| {
                std.debug.print("rex-paste: connection failed ({s}); resending chunk {d}\n", .{ @errorName(err), i });
                queue.note(@errorName(err));
                queue.retry(i);
                self.stop();
                self.open() catch |e| return queue.note(@errorName(e));
                continue;
            };
            queue.finish(done);
        }
    }

    /// Sends one request; true when the receiver needs no more chunks of the transfer.
    fn send(self: *Worker, queue: *Queue, line: []const u8) !bool {
        const child = &self.child.?;
        // A backstop for a worker that hangs: the rex CLI already times out each request.
        const timeout_ms = 2 * 1000 * request_timeout_s;
        const deadline = deadlineAfter(self.io, timeout_ms);
        var header: [8]u8 = undefined;
        _ = try std.mem.print(&header, "{x:0>8}", .{line.len});
        try writeAll(self.io, child.stdin.?.handle, &header, deadline);
        try writeAll(self.io, child.stdin.?.handle, line, deadline);
        var buffer: [4096]u8 = undefined;
        const reply_line = try readLine(self.io, child.stdout.?.handle, &buffer, timeout_ms);
        const Response = struct { ok: bool, @"error": ?[]const u8 = null, done: bool = false };
        const response = try std.json.parseFromSlice(Response, gpa, reply_line, .{ .ignore_unknown_fields = true });
        defer response.deinit();
        if (!response.value.ok) {
            const message = response.value.@"error" orelse "Remote write failed";
            std.debug.print("rex-paste: {s}\n", .{message});
            queue.note(message);
            return error.RemoteWriteFailed;
        }
        return response.value.done;
    }

    fn stop(self: *Worker) void {
        // SIGKILL, not Child.kill's SIGTERM: a stalled worker must not block the pool from exiting.
        if (self.child) |*child| {
            if (child.id) |pid| posix.kill(pid, .KILL) catch {};
            _ = child.wait(self.io) catch {};
        }
        self.child = null;
    }
};

/// The chunks of one transfer, which the workers take one at a time, so a slow connection
/// sends fewer. A chunk whose connection fails goes back once for any connection: connections
/// through a tunnel stall or drop one at a time, and the receiver takes a chunk it already
/// has without change.
const Queue = struct {
    io: Io,
    lines: []const []const u8,
    resend: std.ArrayList(usize), // has room for every chunk
    resent: []bool,
    next: usize = 0,
    pending: usize, // chunks not yet acknowledged
    done: bool = false, // the receiver needs no more chunks
    failed: bool = false,
    reason: ?[]const u8 = null, // the first failure, in reason_buf
    reason_buf: [512]u8 = undefined,
    mutex: Io.Mutex = .init,
    changed: Io.Condition = .init,

    /// The next chunk to send, waiting while others are in flight; null when there is no more.
    fn take(q: *Queue) ?usize {
        q.mutex.lockUncancelable(q.io);
        defer q.mutex.unlock(q.io);
        while (!q.done and !q.failed and q.pending > 0) {
            if (q.resend.pop()) |i| return i;
            if (q.next < q.lines.len) {
                q.next += 1;
                return q.next - 1;
            }
            q.changed.waitUncancelable(q.io, &q.mutex);
        }
        return null;
    }

    fn finish(q: *Queue, done: bool) void {
        q.mutex.lockUncancelable(q.io);
        defer q.mutex.unlock(q.io);
        q.pending -= 1;
        q.done = q.done or done;
        q.changed.broadcast(q.io);
    }

    fn retry(q: *Queue, i: usize) void {
        q.mutex.lockUncancelable(q.io);
        defer q.mutex.unlock(q.io);
        if (q.resent[i]) q.failed = true else {
            q.resent[i] = true;
            q.resend.appendAssumeCapacity(i);
        }
        q.changed.broadcast(q.io);
    }

    fn note(q: *Queue, reason: []const u8) void {
        q.mutex.lockUncancelable(q.io);
        defer q.mutex.unlock(q.io);
        if (q.reason != null) return;
        const len = @min(reason.len, q.reason_buf.len);
        @memcpy(q.reason_buf[0..len], reason[0..len]);
        q.reason = q.reason_buf[0..len];
    }
};

/// Sends the chunks in parallel; the reason on failure, else null.
fn sendChunks(allocator: std.mem.Allocator, workers: []Worker, payload: *const Payload, request: PoolRequest) !?[]const u8 {
    try validHex(request.transfer_id, 32);
    const count = chunkCount(payload.data.len);
    const lines = try allocator.alloc([]const u8, count);
    for (lines, 0..) |*line, i| line.* = try payload.chunk(allocator, i * chunk_size, request);
    const resent = try allocator.alloc(bool, count);
    @memset(resent, false);
    var queue: Queue = .{
        .io = workers[0].io,
        .lines = lines,
        .resend = try .initCapacity(allocator, count),
        .resent = resent,
        .pending = count,
    };
    const active = workers[0..@min(workers.len, count)];
    const threads = try allocator.alloc(std.Thread, active.len);
    var spawned: usize = 0;
    {
        defer for (threads[0..spawned]) |t| t.join();
        for (active, threads) |*worker, *thread| {
            thread.* = try std.Thread.spawn(.{}, Worker.run, .{ worker, &queue });
            spawned += 1;
        }
    }
    if (queue.done or queue.pending == 0) return null;
    return queue.reason orelse "TransferFailed";
}

const PoolPaths = struct { lock: []const u8, socket: []const u8, settings: []const u8 };

/// One lock per host; the socket name also covers the pool settings, so a client never talks
/// to a pool that is being replaced. The settings are " <connections> <max_size> <binary>\n",
/// where the binary's modification time stands for its version.
fn poolPaths(store: Store, host: []const u8) !PoolPaths {
    const exe = try std.process.executablePathAlloc(store.io, gpa);
    const binary = (try Dir.cwd().statFile(store.io, exe, .{})).mtime.nanoseconds;
    const settings = try gpa.print(" {d} {d} {d}\n", .{ config.connections, config.max_size, binary });
    const host_key = sha256Hex(host);
    const settings_key = sha256Hex(try gpa.print("{s}\x00{s}", .{ host, settings }));
    return .{
        .lock = try gpa.print("pool-{s}.lock", .{host_key[0..16]}),
        .socket = try gpa.print("{s}/pool-{s}.sock", .{ store.path, settings_key[0..16] }),
        .settings = settings,
    };
}

// SIGTERM from a replacing pool: finish the current transfer, then exit.
var stop_requested = std.atomic.Value(bool).init(false);
fn requestStop(_: posix.SIG) callconv(.c) void {
    stop_requested.store(true, .monotonic);
}

/// The pools' stderr, shared with their workers: why a pool could not start or stopped.
/// ponytail: appended and never trimmed; it only grows when pools fail.
fn poolLog(store: Store) ![]const u8 {
    return std.fs.path.join(gpa, &.{ std.fs.path.dirname(store.path).?, "pool.log" });
}

/// Keeps `connections` workers, each running the `rex` CLI, connected to `host` and sends
/// requests from the local socket until the Rex server `owner` exits. One pool runs per host.
fn serve(store: Store, rex: []const u8, host: []const u8, owner: posix.pid_t) !void {
    if (!is_mac) return error.SenderRequiresMacOS;
    const io = store.io;
    const log = try posix.openat(posix.AT.FDCWD, try poolLog(store), .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o600);
    if (std.c.dup2(log, posix.STDERR_FILENO) < 0) return error.PoolLogFailed;
    const paths = try poolPaths(store, host);
    const lock = try store.openFile(paths.lock, true, true);
    defer lock.close(io);
    // The lock file records the pid and the settings. A pool with other settings is replaced.
    const settings = paths.settings;
    if (!try lock.tryLock(io, .exclusive)) {
        var buf: [64]u8 = undefined;
        const running = buf[0..try lock.readPositionalAll(io, &buf, 0)];
        const space = std.mem.findScalar(u8, running, ' ') orelse return;
        if (eq(running[space..], settings)) return;
        const pid = std.fmt.parseInt(posix.pid_t, running[0..space], 10) catch return;
        posix.kill(pid, .TERM) catch {};
        try lock.lock(io, .exclusive);
    }
    defer lock.unlock(io);
    try lock.setLength(io, 0);
    try lock.writePositionalAll(io, try gpa.print("{d}{s}", .{ std.c.getpid(), settings }), 0);

    Dir.cwd().deleteFile(io, paths.socket) catch |err| if (err != error.FileNotFound) return err;
    const address = try Io.net.UnixAddress.init(paths.socket);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    defer Dir.cwd().deleteFile(io, paths.socket) catch {};

    const exe_dir = try std.process.executableDirPathAlloc(io, gpa);
    const worker_script = try std.fs.path.join(gpa, &.{ exe_dir, "..", "worker.lua" });
    const timeout = std.fmt.comptimePrint("{d}s", .{request_timeout_s});
    const argv = [_][]const u8{ rex, "--timeout", timeout, "-S", host, "do", worker_script };
    const workers = try gpa.alloc(Worker, config.connections);
    for (workers) |*worker| worker.* = .{ .io = io, .argv = &argv };
    defer for (workers) |*worker| worker.stop();
    {
        const threads = try gpa.alloc(std.Thread, workers.len);
        defer gpa.free(threads);
        var spawned: usize = 0;
        defer for (threads[0..spawned]) |t| t.join();
        for (workers, threads) |*worker, *thread| {
            thread.* = try std.Thread.spawn(.{}, Worker.start, .{worker});
            spawned += 1;
        }
    }
    // Workers that could not connect connect again when they have chunks to send.
    for (workers) |worker| {
        if (worker.child != null) break;
    } else return error.WorkerNotReady;

    posix.sigaction(.TERM, &.{
        .handler = .{ .handler = requestStop },
        .mask = posix.sigemptyset(),
        .flags = 0,
    }, null);
    while (!stop_requested.load(.monotonic)) {
        posix.kill(owner, @fromBackingInt(0)) catch return; // signal 0: is the Rex server alive?
        var polls = [_]posix.pollfd{.{ .fd = server.socket.handle, .events = posix.POLL.IN, .revents = 0 }};
        if (try posix.poll(&polls, 1000) == 0) continue;
        const client = try server.accept(io);
        defer client.close(io);
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        try handle(arena.allocator(), store, workers, client);
    }
}

fn handle(allocator: std.mem.Allocator, store: Store, workers: []Worker, stream: Io.net.Stream) !void {
    const io = store.io;
    // A bad request or unreadable payload fails only this request and keeps the worker connections.
    var buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    const line = reader.interface.takeDelimiterExclusive('\n') catch |err|
        return reply(io, stream, .{ .ok = false, .message = @errorName(err) });
    const request = std.json.parseFromSliceLeaky(PoolRequest, allocator, line, .{}) catch |err|
        return reply(io, stream, .{ .ok = false, .message = @errorName(err) });
    const payload = Payload.read(store, request) catch |err|
        return reply(io, stream, .{ .ok = false, .message = @errorName(err) });
    defer gpa.free(payload.data);
    // Failed connections were already replaced, so the pool keeps serving.
    const failure = sendChunks(allocator, workers, &payload, request) catch |err| @errorName(err);
    if (failure) |message| return reply(io, stream, .{ .ok = false, .message = message });
    reply(io, stream, .{ .ok = true, .bytes = payload.data.len, .sha256 = payload.sha256[0..] });
}

fn reply(io: Io, stream: Io.net.Stream, value: anytype) void {
    var buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    std.json.Stringify.value(value, .{}, &writer.interface) catch return;
    writer.interface.flush() catch {};
}

fn poolUnavailable(store: Store) error{PoolUnavailable} {
    std.debug.print("rex-paste: the pool did not answer; see {s}\n", .{poolLog(store) catch "pool.log"});
    return error.PoolUnavailable;
}

/// Hands a transfer to the pool, which Lua starts before calling this, and prints its reply.
fn send(store: Store, host: []const u8, request: PoolRequest) !void {
    const io = store.io;
    const address = try Io.net.UnixAddress.init((try poolPaths(store, host)).socket);
    // The pool creates its socket right away; workers that are still connecting just delay the reply.
    const deadline = deadlineAfter(io, 10_000);
    const stream = while (true) {
        if (address.connect(io)) |stream| break stream else |err| switch (err) {
            error.FileNotFound, error.ConnectionRefused => {},
            else => return err,
        }
        if (Io.Timestamp.now(io, .awake).durationTo(deadline).nanoseconds <= 0) return poolUnavailable(store);
        try io.sleep(.fromMilliseconds(20), .awake);
    };
    defer stream.close(io);
    var writer = stream.writer(io, &.{});
    try std.json.Stringify.value(request, .{ .emit_null_optional_fields = false }, &writer.interface);
    try writer.interface.writeByte('\n');
    var buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    const response = try reader.interface.allocRemaining(gpa, .limited(4096));
    if (response.len == 0) return poolUnavailable(store);
    const Response = struct { ok: bool, message: ?[]const u8 = null };
    const parsed = try std.json.parseFromSliceLeaky(Response, gpa, response, .{ .ignore_unknown_fields = true });
    if (!parsed.ok) {
        std.debug.print("rex-paste: {s}\n", .{parsed.message orelse "transfer failed"});
        return error.TransferFailed;
    }
    try File.stdout().writeStreamingAll(io, response);
}

const Command = enum { clipboard, prepare, send, serve, push, lookup, discard, progress };

const usage =
    \\usage: rex-paste clipboard
    \\       rex-paste prepare <image>
    \\       rex-paste send image|file <path> <host> <session_id> <block_id> <transfer_id>
    \\       rex-paste serve <rex> <host> <owner_pid>
    \\       rex-paste push < chunk.json
    \\       rex-paste lookup <sha256>
    \\       rex-paste discard <transfer_id>
    \\       rex-paste progress <transfer_id> <label>
    \\
;

fn readPath(io: Io, path: []const u8, max: usize) ![]u8 {
    return Dir.cwd().readFileAlloc(io, path, gpa, .limited(max + 1));
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const all = try init.minimal.args.toSlice(init.arena.allocator());
    const command = std.meta.stringToEnum(Command, if (all.len > 1) all[1] else "") orelse return error.InvalidArguments;
    const args = all[@min(all.len, 2)..];
    const arity: usize = switch (command) {
        .clipboard, .push => 0,
        .prepare, .lookup, .discard => 1,
        .progress => 2,
        .serve => 3,
        .send => 6,
    };
    if (args.len != arity) return error.InvalidArguments;
    try loadConfig(init.environ_map);
    const home = init.environ_map.get("HOME") orelse return error.HomeNotSet;
    const store = try Store.init(io, home);
    defer store.close();
    switch (command) {
        .clipboard => {
            if (!is_mac) return error.ClipboardNotSupported;
            const board = if (init.environ_map.get("REX_PASTE_TEST_BOARD")) |name| try gpa.dupeSentinel(u8, name, 0) else null;
            var ptr: ?[*]u8 = null;
            var len: usize = 0;
            const kind = clipboard_read(if (board) |name| name.ptr else null, &ptr, &len);
            if (kind < 0) return error.ClipboardReadFailed;
            defer std.c.free(ptr);
            const data = ptr.?[0..len];
            const id = try randomId(io);
            switch (kind) {
                0 => try output(io, .{ .kind = "text", .text = data }),
                2 => try output(io, .{ .kind = "file", .path = data, .transfer_id = id[0..] }),
                else => {
                    try store.cleanup();
                    const image = try storeImage(store, data, false);
                    try output(io, .{ .kind = "image", .path = image.path, .sha256 = image.sha256[0..], .transfer_id = id[0..] });
                },
            }
        },
        .prepare => {
            const image = try storeImage(store, try readPath(io, args[0], source_limit), true);
            try output(io, .{ .path = image.path, .sha256 = image.sha256[0..] });
        },
        .send => {
            var request: PoolRequest = .{ .session_id = args[3], .block_id = args[4], .transfer_id = args[5] };
            try validHex(request.transfer_id, 32);
            if (eq(args[0], "image")) {
                const image = try storeImage(store, try readPath(io, args[1], source_limit), true);
                request.token = try gpa.dupe(u8, &image.sha256);
            } else if (eq(args[0], "file")) {
                request.path = try Dir.cwd().realPathFileAlloc(io, args[1], gpa);
            } else return error.InvalidArguments;
            try send(store, args[2], request);
        },
        .serve => try serve(store, args[0], args[1], try std.fmt.parseInt(posix.pid_t, args[2], 10)),
        .push => {
            var buffer: [4096]u8 = undefined;
            var stdin = File.stdin().readerStreaming(io, &buffer);
            const input = try readAll(&stdin, 65536);
            try push(store, try std.json.parseFromSliceLeaky(Push, gpa, input, .{ .ignore_unknown_fields = true }));
        },
        .lookup => {
            const data = storedImage(store, args[0]) catch |err| {
                if (err == error.FileNotFound) return output(io, .{ .path = no_path });
                return err;
            };
            try output(io, .{ .path = try imagePath(store, args[0], data) });
        },
        .progress => try progress(store, args[0], args[1]),
        .discard => {
            try validHex(args[0], 32);
            inline for (.{ ".part", ".state" }) |ext| {
                const name = try gpa.print("{s}" ++ ext, .{args[0]});
                store.dir.deleteFile(io, name) catch |err| if (err != error.FileNotFound) return err;
            }
            try output(io, .{});
        },
    }
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        if (err == error.InvalidArguments) std.debug.print("{s}", .{usage});
        std.debug.print("rex-paste: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}
