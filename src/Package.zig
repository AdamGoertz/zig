const Package = @This();

const builtin = @import("builtin");
const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;
const assert = std.debug.assert;
const log = std.log.scoped(.package);
const main = @import("main.zig");

const Compilation = @import("Compilation.zig");
const Module = @import("Module.zig");
const ThreadPool = @import("ThreadPool.zig");
const WaitGroup = @import("WaitGroup.zig");
const Cache = @import("Cache.zig");
const build_options = @import("build_options");
const Manifest = @import("Manifest.zig");

pub const Table = std.StringHashMapUnmanaged(*Package);

root_src_directory: Compilation.Directory,
/// Relative to `root_src_directory`. May contain path separators.
root_src_path: []const u8,
table: Table = .{},
parent: ?*Package = null,
/// Whether to free `root_src_directory` on `destroy`.
root_src_directory_owned: bool = false,
/// This information can be recovered from 'table', but it's more convenient to store on the package.
name: []const u8,

/// Allocate a Package. No references to the slices passed are kept.
pub fn create(
    gpa: Allocator,
    name: []const u8,
    /// Null indicates the current working directory
    root_src_dir_path: ?[]const u8,
    /// Relative to root_src_dir_path
    root_src_path: []const u8,
) !*Package {
    const ptr = try gpa.create(Package);
    errdefer gpa.destroy(ptr);

    const owned_dir_path = if (root_src_dir_path) |p| try gpa.dupe(u8, p) else null;
    errdefer if (owned_dir_path) |p| gpa.free(p);

    const owned_src_path = try gpa.dupe(u8, root_src_path);
    errdefer gpa.free(owned_src_path);

    const owned_name = try gpa.dupe(u8, name);
    errdefer gpa.free(owned_name);

    ptr.* = .{
        .root_src_directory = .{
            .path = owned_dir_path,
            .handle = if (owned_dir_path) |p| try fs.cwd().openDir(p, .{}) else fs.cwd(),
        },
        .root_src_path = owned_src_path,
        .root_src_directory_owned = true,
        .name = owned_name,
    };

    return ptr;
}

pub fn createWithDir(
    gpa: Allocator,
    name: []const u8,
    directory: Compilation.Directory,
    /// Relative to `directory`. If null, means `directory` is the root src dir
    /// and is owned externally.
    root_src_dir_path: ?[]const u8,
    /// Relative to root_src_dir_path
    root_src_path: []const u8,
) !*Package {
    const ptr = try gpa.create(Package);
    errdefer gpa.destroy(ptr);

    const owned_src_path = try gpa.dupe(u8, root_src_path);
    errdefer gpa.free(owned_src_path);

    const owned_name = try gpa.dupe(u8, name);
    errdefer gpa.free(owned_name);

    if (root_src_dir_path) |p| {
        const owned_dir_path = try directory.join(gpa, &[1][]const u8{p});
        errdefer gpa.free(owned_dir_path);

        ptr.* = .{
            .root_src_directory = .{
                .path = owned_dir_path,
                .handle = try directory.handle.openDir(p, .{}),
            },
            .root_src_directory_owned = true,
            .root_src_path = owned_src_path,
            .name = owned_name,
        };
    } else {
        ptr.* = .{
            .root_src_directory = directory,
            .root_src_directory_owned = false,
            .root_src_path = owned_src_path,
            .name = owned_name,
        };
    }
    return ptr;
}

/// Free all memory associated with this package. It does not destroy any packages
/// inside its table; the caller is responsible for calling destroy() on them.
pub fn destroy(pkg: *Package, gpa: Allocator) void {
    gpa.free(pkg.root_src_path);
    gpa.free(pkg.name);

    if (pkg.root_src_directory_owned) {
        // If root_src_directory.path is null then the handle is the cwd()
        // which shouldn't be closed.
        if (pkg.root_src_directory.path) |p| {
            gpa.free(p);
            pkg.root_src_directory.handle.close();
        }
    }

    pkg.deinitTable(gpa);
    gpa.destroy(pkg);
}

/// Only frees memory associated with the table.
pub fn deinitTable(pkg: *Package, gpa: Allocator) void {
    pkg.table.deinit(gpa);
}

pub fn add(pkg: *Package, gpa: Allocator, package: *Package) !void {
    try pkg.table.ensureUnusedCapacity(gpa, 1);
    pkg.table.putAssumeCapacityNoClobber(package.name, package);
}

pub fn addAndAdopt(parent: *Package, gpa: Allocator, child: *Package) !void {
    assert(child.parent == null); // make up your mind, who is the parent??
    child.parent = parent;
    return parent.add(gpa, child);
}

pub const build_zig_basename = "build.zig";

pub fn fetchAndAddDependencies(
    pkg: *Package,
    arena: Allocator,
    thread_pool: *ThreadPool,
    http_client: *std.http.Client,
    directory: Compilation.Directory,
    global_cache_directory: Compilation.Directory,
    local_cache_directory: Compilation.Directory,
    dependencies_source: *std.ArrayList(u8),
    build_roots_source: *std.ArrayList(u8),
    name_prefix: []const u8,
    color: main.Color,
) !void {
    const max_bytes = 10 * 1024 * 1024;
    const gpa = thread_pool.allocator;
    const build_zig_zon_bytes = directory.handle.readFileAllocOptions(
        arena,
        Manifest.basename,
        max_bytes,
        null,
        1,
        0,
    ) catch |err| switch (err) {
        error.FileNotFound => {
            // Handle the same as no dependencies.
            return;
        },
        else => |e| return e,
    };

    var ast = try std.zig.Ast.parse(gpa, build_zig_zon_bytes, .zon);
    defer ast.deinit(gpa);

    if (ast.errors.len > 0) {
        const file_path = try directory.join(arena, &.{Manifest.basename});
        try main.printErrsMsgToStdErr(gpa, arena, ast, file_path, color);
        return error.PackageFetchFailed;
    }

    var manifest = try Manifest.parse(gpa, ast);
    defer manifest.deinit(gpa);

    if (manifest.errors.len > 0) {
        const ttyconf: std.debug.TTY.Config = switch (color) {
            .auto => std.debug.detectTTYConfig(std.io.getStdErr()),
            .on => .escape_codes,
            .off => .no_color,
        };
        const file_path = try directory.join(arena, &.{Manifest.basename});
        for (manifest.errors) |msg| {
            Report.renderErrorMessage(ast, file_path, ttyconf, msg, &.{});
        }
        return error.PackageFetchFailed;
    }

    const report: Report = .{
        .ast = &ast,
        .directory = directory,
        .color = color,
        .arena = arena,
    };

    var any_error = false;
    const deps_list = manifest.dependencies.values();
    for (manifest.dependencies.keys()) |name, i| {
        const dep = deps_list[i];

        const sub_prefix = try std.fmt.allocPrint(arena, "{s}{s}.", .{ name_prefix, name });
        const fqn = sub_prefix[0 .. sub_prefix.len - 1];

        const sub_pkg = try getCachedPackage(
            http_client.allocator,
            global_cache_directory,
            dep,
            build_roots_source,
            fqn,
        ) orelse try fetchAndUnpack(
            thread_pool,
            http_client,
            directory,
            global_cache_directory,
            dep,
            report,
            build_roots_source,
            fqn,
        );

        try pkg.fetchAndAddDependencies(
            arena,
            thread_pool,
            http_client,
            sub_pkg.root_src_directory,
            global_cache_directory,
            local_cache_directory,
            dependencies_source,
            build_roots_source,
            sub_prefix,
            color,
        );

        try addAndAdopt(pkg, gpa, sub_pkg);

        try dependencies_source.writer().print("    pub const {s} = @import(\"{}\");\n", .{
            std.zig.fmtId(fqn), std.zig.fmtEscapes(fqn),
        });
    }

    if (any_error) return error.InvalidBuildManifestFile;
}

pub fn createFilePkg(
    gpa: Allocator,
    name: []const u8,
    cache_directory: Compilation.Directory,
    basename: []const u8,
    contents: []const u8,
) !*Package {
    const rand_int = std.crypto.random.int(u64);
    const tmp_dir_sub_path = "tmp" ++ fs.path.sep_str ++ Manifest.hex64(rand_int);
    {
        var tmp_dir = try cache_directory.handle.makeOpenPath(tmp_dir_sub_path, .{});
        defer tmp_dir.close();
        try tmp_dir.writeFile(basename, contents);
    }

    var hh: Cache.HashHelper = .{};
    hh.addBytes(build_options.version);
    hh.addBytes(contents);
    const hex_digest = hh.final();

    const o_dir_sub_path = "o" ++ fs.path.sep_str ++ hex_digest;
    try renameTmpIntoCache(cache_directory.handle, tmp_dir_sub_path, o_dir_sub_path);

    return createWithDir(gpa, name, cache_directory, o_dir_sub_path, basename);
}

const Report = struct {
    ast: *const std.zig.Ast,
    directory: Compilation.Directory,
    color: main.Color,
    arena: Allocator,

    fn fail(
        report: Report,
        tok: std.zig.Ast.TokenIndex,
        comptime fmt_string: []const u8,
        fmt_args: anytype,
    ) error{ PackageFetchFailed, OutOfMemory } {
        return failWithNotes(report, &.{}, tok, fmt_string, fmt_args);
    }

    fn failWithNotes(
        report: Report,
        notes: []const Compilation.AllErrors.Message,
        tok: std.zig.Ast.TokenIndex,
        comptime fmt_string: []const u8,
        fmt_args: anytype,
    ) error{ PackageFetchFailed, OutOfMemory } {
        const ttyconf: std.debug.TTY.Config = switch (report.color) {
            .auto => std.debug.detectTTYConfig(std.io.getStdErr()),
            .on => .escape_codes,
            .off => .no_color,
        };
        const file_path = try report.directory.join(report.arena, &.{Manifest.basename});
        renderErrorMessage(report.ast.*, file_path, ttyconf, .{
            .tok = tok,
            .off = 0,
            .msg = try std.fmt.allocPrint(report.arena, fmt_string, fmt_args),
        }, notes);
        return error.PackageFetchFailed;
    }

    fn renderErrorMessage(
        ast: std.zig.Ast,
        file_path: []const u8,
        ttyconf: std.debug.TTY.Config,
        msg: Manifest.ErrorMessage,
        notes: []const Compilation.AllErrors.Message,
    ) void {
        const token_starts = ast.tokens.items(.start);
        const start_loc = ast.tokenLocation(0, msg.tok);
        Compilation.AllErrors.Message.renderToStdErr(.{ .src = .{
            .msg = msg.msg,
            .src_path = file_path,
            .line = @intCast(u32, start_loc.line),
            .column = @intCast(u32, start_loc.column),
            .span = .{
                .start = token_starts[msg.tok],
                .end = @intCast(u32, token_starts[msg.tok] + ast.tokenSlice(msg.tok).len),
                .main = token_starts[msg.tok] + msg.off,
            },
            .source_line = ast.source[start_loc.line_start..start_loc.line_end],
            .notes = notes,
        } }, ttyconf);
    }
};

const PackageSource = struct {
    uri: std.Uri,
    /// Directory to which relative paths in URI are relative.
    root_dir: Compilation.Directory,
    resource: Resource,
    file_type: FileType,

    const SourceType = enum {
        file,
        http_request,
    };

    const FileType = enum {
        @"tar.gz",
        @"tar.xz",
        directory,
    };

    const Resource = union(SourceType) {
        file: fs.File,
        http_request: std.http.Client.Request,
    };

    pub const PackageLocation = struct {
        hash: [Manifest.Hash.digest_length]u8,
        dir_path: []const u8,

        pub fn deinit(pl: *PackageLocation, allocator: Allocator) void {
            allocator.free(pl.dir_path);
            pl.* = undefined;
        }
    };

    pub fn init(uri: std.Uri, directory: Compilation.Directory, http_client: *std.http.Client) !PackageSource {
        const source_type = try getPackageSourceType(uri);

        return .{
            .uri = uri,
            .root_dir = directory,
            .resource = switch (source_type) {
                .file => Resource{
                    .file = try directory.handle.openFile(uri.path, .{}),
                },
                .http_request => Resource{
                    .http_request = try http_client.request(uri, .{}, .{}),
                },
            },
            .file_type = try getFileType(uri),
        };
    }

    pub fn deinit(ps: *PackageSource) void {
        switch (ps.resource) {
            .file => |*file| file.close(),
            .http_request => |*req| req.deinit(),
        }
    }

    pub fn unpack(ps: *PackageSource, allocator: Allocator, thread_pool: *ThreadPool, global_cache_directory: Compilation.Directory) !PackageLocation {
        if (!ps.needsUnpacking()) {
            const package_path = try ps.getUnpackedPackagePath(allocator, global_cache_directory, null);
            errdefer allocator.free(package_path);
            var package_dir = try fs.openIterableDirAbsolute(package_path, .{});
            defer package_dir.close();
            const actual_hash = try computePackageHash(thread_pool, .{ .dir = package_dir.dir });
            return .{
                .hash = actual_hash,
                .dir_path = package_path,
            };
        }

        const s = fs.path.sep_str;
        const rand_int = std.crypto.random.int(u64);
        const tmp_dir_sub_path = "tmp" ++ s ++ Manifest.hex64(rand_int);

        var tmp_directory: Compilation.Directory = d: {
            const path = try global_cache_directory.join(allocator, &.{tmp_dir_sub_path});
            errdefer allocator.free(path);

            const iterable_dir = try global_cache_directory.handle.makeOpenPathIterable(tmp_dir_sub_path, .{});
            errdefer iterable_dir.close();

            break :d .{
                .path = path,
                .handle = iterable_dir.dir,
            };
        };
        defer tmp_directory.closeAndFree(allocator);

        switch (ps.file_type) {
            .@"tar.gz" => {
                // I observed the gzip stream to read 1 byte at a time, so I am using a
                // buffered reader on the front of it.
                switch (ps.resource) {
                    inline else => |*r| try unpackTarball(allocator, r.reader(), tmp_directory.handle, std.compress.gzip),
                }
            },
            .@"tar.xz" => {
                // I have not checked what buffer sizes the xz decompression implementation uses
                // by default, so the same logic applies for buffering the reader as for gzip.
                switch (ps.resource) {
                    inline else => |*r| try unpackTarball(allocator, r.reader(), tmp_directory.handle, std.compress.xz),
                }
            },
            .directory => unreachable,
        }

        // TODO: delete files not included in the package prior to computing the package hash.
        // for example, if the ini file has directives to include/not include certain files,
        // apply those rules directly to the filesystem right here. This ensures that files
        // not protected by the hash are not present on the file system.

        const actual_hash = try computePackageHash(thread_pool, .{ .dir = tmp_directory.handle });

        const unpacked_path = try ps.getUnpackedPackagePath(allocator, global_cache_directory, actual_hash);
        errdefer allocator.free(unpacked_path);

        const relative_unpacked_path = try fs.path.relative(allocator, global_cache_directory.path.?, unpacked_path);
        defer allocator.free(relative_unpacked_path);
        try renameTmpIntoCache(global_cache_directory.handle, tmp_dir_sub_path, relative_unpacked_path);

        return .{
            .hash = actual_hash,
            .dir_path = unpacked_path,
        };
    }

    /// Get the path to the unpacked package.
    /// The returned path is owned by the caller and must be freed using the provided allocator.
    pub fn getUnpackedPackagePath(
        ps: PackageSource,
        allocator: Allocator,
        global_cache_dir: Compilation.Directory,
        hash_digest: ?[Manifest.Hash.digest_length]u8,
    ) ![]const u8 {
        if (ps.needsUnpacking()) {
            assert(hash_digest != null);

            const s = fs.path.sep_str;
            const pkg_dir_sub_path = "p" ++ s ++ Manifest.hexDigest(hash_digest.?);

            return try global_cache_dir.join(allocator, &.{pkg_dir_sub_path});
        }

        // Resolve path to package relative to root_dir
        return try fs.path.resolve(allocator, &.{ ps.root_dir.path.?, ps.uri.path });
    }

    fn needsUnpacking(ps: PackageSource) bool {
        return switch (ps.file_type) {
            .directory => false,
            .@"tar.gz", .@"tar.xz" => true,
        };
    }

    fn getPackageSourceType(uri: std.Uri) error{UnknownScheme}!SourceType {
        const package_source_map = std.ComptimeStringMap(
            SourceType,
            .{
                .{ "file", .file },
                .{ "http", .http_request },
                .{ "https", .http_request },
            },
        );
        return package_source_map.get(uri.scheme) orelse error.UnknownScheme;
    }

    fn getFileType(uri: std.Uri) error{UnknownFileType}!FileType {
        return if (mem.endsWith(u8, uri.path, ".tar.gz"))
            .@"tar.gz"
        else if (mem.endsWith(u8, uri.path, ".tar.xz"))
            .@"tar.xz"
        else if (mem.endsWith(u8, uri.path, "/"))
            .directory
            // Other types here
        else
            error.UnknownFileType;
    }
};

fn getCachedPackage(
    gpa: Allocator,
    global_cache_directory: Compilation.Directory,
    dep: Manifest.Dependency,
    build_roots_source: *std.ArrayList(u8),
    fqn: []const u8,
) !?*Package {
    const s = fs.path.sep_str;
    // Check if the expected_hash is already present in the global package
    // cache, and thereby avoid both fetching and unpacking.
    if (dep.hash) |h| cached: {
        const hex_multihash_len = 2 * Manifest.multihash_len;
        const hex_digest = h[0..hex_multihash_len];
        const pkg_dir_sub_path = "p" ++ s ++ hex_digest;
        var pkg_dir = global_cache_directory.handle.openDir(pkg_dir_sub_path, .{}) catch |err| switch (err) {
            error.FileNotFound => break :cached,
            else => |e| return e,
        };
        errdefer pkg_dir.close();

        const ptr = try gpa.create(Package);
        errdefer gpa.destroy(ptr);

        const owned_src_path = try gpa.dupe(u8, build_zig_basename);
        errdefer gpa.free(owned_src_path);

        const owned_name = try gpa.dupe(u8, fqn);
        errdefer gpa.free(owned_name);

        const build_root = try global_cache_directory.join(gpa, &.{pkg_dir_sub_path});
        errdefer gpa.free(build_root);

        try build_roots_source.writer().print("    pub const {s} = \"{}\";\n", .{
            std.zig.fmtId(fqn), std.zig.fmtEscapes(build_root),
        });

        ptr.* = .{
            .root_src_directory = .{
                .path = build_root,
                .handle = pkg_dir,
            },
            .root_src_directory_owned = true,
            .root_src_path = owned_src_path,
            .name = owned_name,
        };

        return ptr;
    }

    return null;
}

fn fetchAndUnpack(
    thread_pool: *ThreadPool,
    http_client: *std.http.Client,
    directory: Compilation.Directory,
    global_cache_directory: Compilation.Directory,
    dep: Manifest.Dependency,
    report: Report,
    build_roots_source: *std.ArrayList(u8),
    fqn: []const u8,
) !*Package {
    const gpa = http_client.allocator;

    const uri = try std.Uri.parse(dep.url);

    // If so, fetch it
    var package_source = PackageSource.init(uri, directory, http_client) catch |err| switch (err) {
        error.UnknownFileType => return report.fail(dep.url_tok, "unknown file type", .{}),
        error.UnknownScheme => return report.fail(dep.url_tok, "unknown URI scheme: {s}", .{ uri.scheme }),
        else => return err,
    };
    defer package_source.deinit();

    var package_location = try package_source.unpack(gpa, thread_pool, global_cache_directory);
    defer package_location.deinit(gpa);

    const actual_hex = Manifest.hexDigest(package_location.hash);
    if (dep.hash) |h| {
        if (!mem.eql(u8, h, &actual_hex)) {
            return report.fail(dep.hash_tok, "hash mismatch: expected: {s}, found: {s}", .{
                h, actual_hex,
            });
        }
    } else {
        const notes: [1]Compilation.AllErrors.Message = .{.{ .plain = .{
            .msg = try std.fmt.allocPrint(report.arena, "expected .hash = \"{s}\",", .{&actual_hex}),
        } }};
        return report.failWithNotes(&notes, dep.url_tok, "url field is missing corresponding hash field", .{});
    }

    try build_roots_source.writer().print("    pub const {s} = \"{}\";\n", .{
        std.zig.fmtId(fqn), std.zig.fmtEscapes(package_location.dir_path),
    });

    return create(gpa, fqn, package_location.dir_path, build_zig_basename);
}

fn unpackTarball(
    gpa: Allocator,
    reader: anytype,
    out_dir: fs.Dir,
    comptime compression: type,
) !void {
    var br = std.io.bufferedReaderSize(std.crypto.tls.max_ciphertext_record_len, reader);

    var decompress = try compression.decompress(gpa, br.reader());
    defer decompress.deinit();

    try std.tar.pipeToFileSystem(out_dir, decompress.reader(), .{
        .strip_components = 1,
        // TODO: we would like to set this to executable_bit_only, but two
        // things need to happen before that:
        // 1. the tar implementation needs to support it
        // 2. the hashing algorithm here needs to support detecting the is_executable
        //    bit on Windows from the ACLs (see the isExecutable function).
        .mode_mode = .ignore,
    });
}

const HashedFile = struct {
    path: []const u8,
    hash: [Manifest.Hash.digest_length]u8,
    failure: Error!void,

    const Error = fs.File.OpenError || fs.File.ReadError || fs.File.StatError;

    fn lessThan(context: void, lhs: *const HashedFile, rhs: *const HashedFile) bool {
        _ = context;
        return mem.lessThan(u8, lhs.path, rhs.path);
    }
};

fn computePackageHash(
    thread_pool: *ThreadPool,
    pkg_dir: fs.IterableDir,
) ![Manifest.Hash.digest_length]u8 {
    const gpa = thread_pool.allocator;

    // We'll use an arena allocator for the path name strings since they all
    // need to be in memory for sorting.
    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    // Collect all files, recursively, then sort.
    var all_files = std.ArrayList(*HashedFile).init(gpa);
    defer all_files.deinit();

    var walker = try pkg_dir.walk(gpa);
    defer walker.deinit();

    {
        // The final hash will be a hash of each file hashed independently. This
        // allows hashing in parallel.
        var wait_group: WaitGroup = .{};
        defer wait_group.wait();

        while (try walker.next()) |entry| {
            switch (entry.kind) {
                .Directory => continue,
                .File => {},
                else => return error.IllegalFileTypeInPackage,
            }
            const hashed_file = try arena.create(HashedFile);
            hashed_file.* = .{
                .path = try arena.dupe(u8, entry.path),
                .hash = undefined, // to be populated by the worker
                .failure = undefined, // to be populated by the worker
            };
            wait_group.start();
            try thread_pool.spawn(workerHashFile, .{ pkg_dir.dir, hashed_file, &wait_group });

            try all_files.append(hashed_file);
        }
    }

    std.sort.sort(*HashedFile, all_files.items, {}, HashedFile.lessThan);

    var hasher = Manifest.Hash.init(.{});
    var any_failures = false;
    for (all_files.items) |hashed_file| {
        hashed_file.failure catch |err| {
            any_failures = true;
            std.log.err("unable to hash '{s}': {s}", .{ hashed_file.path, @errorName(err) });
        };
        hasher.update(&hashed_file.hash);
    }
    if (any_failures) return error.PackageHashUnavailable;
    return hasher.finalResult();
}

fn workerHashFile(dir: fs.Dir, hashed_file: *HashedFile, wg: *WaitGroup) void {
    defer wg.finish();
    hashed_file.failure = hashFileFallible(dir, hashed_file);
}

fn hashFileFallible(dir: fs.Dir, hashed_file: *HashedFile) HashedFile.Error!void {
    var buf: [8000]u8 = undefined;
    var file = try dir.openFile(hashed_file.path, .{});
    var hasher = Manifest.Hash.init(.{});
    hasher.update(hashed_file.path);
    hasher.update(&.{ 0, @boolToInt(try isExecutable(file)) });
    while (true) {
        const bytes_read = try file.read(&buf);
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
    }
    hasher.final(&hashed_file.hash);
}

fn isExecutable(file: fs.File) !bool {
    if (builtin.os.tag == .windows) {
        // TODO check the ACL on Windows.
        // Until this is implemented, this could be a false negative on
        // Windows, which is why we do not yet set executable_bit_only above
        // when unpacking the tarball.
        return false;
    } else {
        const stat = try file.stat();
        return (stat.mode & std.os.S.IXUSR) != 0;
    }
}

fn renameTmpIntoCache(
    cache_dir: fs.Dir,
    tmp_dir_sub_path: []const u8,
    dest_dir_sub_path: []const u8,
) !void {
    var handled_missing_dir = false;
    while (true) {
        cache_dir.rename(tmp_dir_sub_path, dest_dir_sub_path) catch |err| switch (err) {
            error.FileNotFound => {
                if (handled_missing_dir) return err;
                cache_dir.makeDir(dest_dir_sub_path[0..1]) catch |mkd_err| switch (mkd_err) {
                    error.PathAlreadyExists => handled_missing_dir = true,
                    else => |e| return e,
                };
                continue;
            },
            error.PathAlreadyExists, error.AccessDenied => {
                // Package has been already downloaded and may already be in use on the system.
                cache_dir.deleteTree(tmp_dir_sub_path) catch |del_err| {
                    std.log.warn("unable to delete temp directory: {s}", .{@errorName(del_err)});
                };
            },
            else => |e| return e,
        };
        break;
    }
}
