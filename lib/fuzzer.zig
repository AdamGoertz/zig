const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const std_options = .{
    .logFn = logOverride,
};

var log_file: ?std.fs.File = null;

fn logOverride(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (builtin.mode != .Debug) return;
    const f = if (log_file) |f| f else f: {
        const f = std.fs.cwd().createFile("libfuzzer.log", .{}) catch @panic("failed to open fuzzer log file");
        log_file = f;
        break :f f;
    };
    const prefix1 = comptime level.asText();
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    f.writer().print(prefix1 ++ prefix2 ++ format ++ "\n", args) catch @panic("failed to write to fuzzer log");
}

export threadlocal var __sancov_lowest_stack: usize = 0;

export fn __sanitizer_cov_8bit_counters_init(start: [*]u8, stop: [*]u8) void {
    std.log.debug("__sanitizer_cov_8bit_counters_init start={*}, stop={*}", .{ start, stop });
}

export fn __sanitizer_cov_pcs_init(pc_start: [*]const usize, pc_end: [*]const usize) void {
    std.log.debug("__sanitizer_cov_pcs_init pc_start={*}, pc_end={*}", .{ pc_start, pc_end });
    fuzzer.pc_range = .{
        .start = @intFromPtr(pc_start),
        .end = @intFromPtr(pc_start),
    };
}

export fn __sanitizer_cov_trace_const_cmp1(arg1: u8, arg2: u8) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_cmp1(arg1: u8, arg2: u8) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_const_cmp2(arg1: u16, arg2: u16) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_cmp2(arg1: u16, arg2: u16) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_const_cmp4(arg1: u32, arg2: u32) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_cmp4(arg1: u32, arg2: u32) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_const_cmp8(arg1: u64, arg2: u64) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_cmp8(arg1: u64, arg2: u64) void {
    handleCmp(@returnAddress(), arg1, arg2);
}

export fn __sanitizer_cov_trace_switch(val: u64, cases_ptr: [*]u64) void {
    const pc = @returnAddress();
    const len = cases_ptr[0];
    const val_size_in_bits = cases_ptr[1];
    const cases = cases_ptr[2..][0..len];
    _ = val;
    fuzzer.visitPc(pc);
    _ = val_size_in_bits;
    _ = cases;
    //std.log.debug("0x{x}: switch on value {d} ({d} bits) with {d} cases", .{
    //    pc, val, val_size_in_bits, cases.len,
    //});
}

export fn __sanitizer_cov_trace_pc_indir(callee: usize) void {
    const pc = @returnAddress();
    _ = callee;
    fuzzer.visitPc(pc);
    //std.log.debug("0x{x}: indirect call to 0x{x}", .{ pc, callee });
}

fn handleCmp(pc: usize, arg1: u64, arg2: u64) void {
    fuzzer.visitPc(pc ^ arg1 ^ arg2);
    //std.log.debug("0x{x}: comparison of {d} and {d}", .{ pc, arg1, arg2 });
}

pub fn Bandit(comptime N: usize) type {
    return struct {
        rewards: [N]u32 = [_]u32{0} ** N,
        counts: [N]u32 = [_]u32{0} ** N,
        squared_rewards: [N]u32 = [_]u32{0} ** N,
        scores: [N]f32 = [_]f32{1000.0} ** N, // Give un-tested mutations a large score to encourage them to be used.
        total: u32 = 0,

        const Self = @This();

        pub fn bestArm(b: Self) usize {
            var best_arm: usize = 0;
            var best_score: f32 = 0.0;
            for (&b.scores, 0..) |score, i| {
                if (score > best_score) {
                    best_score = score;
                    best_arm = i;
                }
            }
            return best_arm;
        }

        pub fn update(b: *Self, arm: usize, reward: u1) void {
            b.rewards[arm] += reward;
            b.counts[arm] += 1;
            b.squared_rewards[arm] += reward * reward;
            b.total += 1;

            for (&b.rewards, &b.counts, &b.squared_rewards, &b.scores) |r, c, sq, *score| {
                if (c == 0) continue;

                const total_reward: f32 = @floatFromInt(r);
                const count: f32 = @floatFromInt(c);
                const squared: f32 = @floatFromInt(sq);

                const avg: f32 = total_reward / count;
                const freq = @log(@as(f32, @floatFromInt(b.total))) / count;
                const variance = squared / count - avg;
                score.* = avg + @sqrt(freq * @min(0.25, variance + @sqrt(2 * freq)));
            }
        }
    };
}

/// Adaptive Multi-armed bandit Havoc fuzzer strategy.
/// For more detail see Wu et al. 'One Fuzzing Stragety to Rule Them All` (2022)
/// https://i.cs.hku.hk/~heming/papers/icse22-fuzzing.pdf
const HavocMAB = struct {
    /// Multi-armed bandit for the stack size
    size_bandit: SizeBandit = .{},
    /// Multi-armed bandits for unit or chunk mutations; one for each size bucket
    type_bandit: [size_buckets]TypeBandit = [_]TypeBandit{.{}} ** size_buckets,
    /// The most recently-produced set of mutations
    last_mutations: ?Mutations = null,

    const max_stack_size = 128;
    const size_buckets = std.math.log2_int(usize, max_stack_size) + 1;

    const SizeBandit = Bandit(size_buckets);
    const TypeBandit = Bandit(@typeInfo(MutationType).Enum.fields.len);

    const MutationType = enum {
        unit,
        chunk,
    };

    const UnitMutation = enum {
        bitflip,
        interesting_value_8,
        interesting_value_16,
        interesting_value_32,
        arithmetic_increase_8,
        arithmetic_decrease_8,
        arithmetic_increase_16,
        arithmetic_decrease_16,
        arithmetic_increase_32,
        arithmetic_decrease_32,
        random_value,
    };

    const ChunkMutation = enum {
        delete_bytes,
        clone_bytes,
        insert_bytes,
        overwrite_bytes,
    };

    pub const Mutations = struct {
        count_log2: usize,
        type: MutationType,
    };

    /// Compute the current best set of mutations and apply them to the input `bytes`.
    /// Returns the set of mutations selected.
    pub fn mutate(h: *HavocMAB, gpa: Allocator, rng: std.Random, input: *std.ArrayListUnmanaged(u8)) Allocator.Error!void {
        const stack_size_log2: u6 = @intCast(h.size_bandit.bestArm());
        const stack_size: usize = @as(usize, 1) << stack_size_log2;
        const best_type: MutationType = @enumFromInt(h.type_bandit[stack_size_log2].bestArm());

        switch (best_type) {
            .unit => applyUnitMutations(rng, input, stack_size),
            .chunk => try applyChunkMutations(gpa, rng, input, stack_size),
        }

        h.last_mutations = .{
            .count_log2 = stack_size_log2,
            .type = best_type,
        };
    }

    fn applyUnitMutations(rng: std.Random, input: *std.ArrayListUnmanaged(u8), num_mutations: usize) void {
        for (0..num_mutations) |_| {
            const rand = rng.uintLessThanBiased(usize, input.items.len * @typeInfo(UnitMutation).Enum.fields.len);
            const mutation: UnitMutation = @enumFromInt(rand / input.items.len);
            const index = rand % input.items.len;

            const endian = rng.enumValue(std.builtin.Endian);
            const values_8 = [_]i8{ std.math.minInt(i8), -1, 0, 1, 16, 32, 64, 100, std.math.maxInt(i8) };
            const values_16 = [_]i16{ std.math.minInt(i16), -129, -1, 0, 1, 128, 255, 256, 512, 1000, 1024, 4096, std.math.maxInt(i16) };
            const values_32 = [_]i32{ std.math.minInt(i32), -100663046, -32769, -1, 0, 1, 32768, 65535, 65536, 100663045, std.math.maxInt(i32) };

            switch (mutation) {
                .bitflip => {
                    const bit_index = rng.int(u3);
                    input.items[index] ^= (@as(u8, 1) << bit_index);
                },
                .interesting_value_8 => {
                    const val_index = rng.uintLessThanBiased(usize, values_8.len);
                    input.items[index] = @bitCast(values_8[val_index]);
                },
                .interesting_value_16 => {
                    const T = i16;
                    if (input.items.len - index < @sizeOf(T)) continue;
                    const val_index = rng.uintLessThanBiased(usize, values_16.len);
                    std.mem.writeInt(T, input.items[index..][0..@sizeOf(T)], values_16[val_index], endian);
                },
                .interesting_value_32 => {
                    const T = i32;
                    if (input.items.len - index < @sizeOf(T)) continue;
                    const val_index = rng.uintLessThanBiased(usize, values_32.len);
                    std.mem.writeInt(T, input.items[index..][0..@sizeOf(T)], values_32[val_index], endian);
                },
                .arithmetic_increase_8 => {
                    input.items[index] +%= rng.int(u8);
                },
                .arithmetic_decrease_8 => {
                    input.items[index] -%= rng.int(u8);
                },
                .arithmetic_increase_16 => {
                    const T = u16;
                    if (input.items.len - index < @sizeOf(T)) continue;
                    const int_bytes = input.items[index..][0..@sizeOf(T)];
                    const val = std.mem.readInt(T, int_bytes, endian);
                    std.mem.writeInt(T, int_bytes, val +% rng.int(T), endian);
                },
                .arithmetic_decrease_16 => {
                    const T = u16;
                    if (input.items.len - index < @sizeOf(T)) continue;
                    const int_bytes = input.items[index..][0..@sizeOf(T)];
                    const val = std.mem.readInt(T, int_bytes, endian);
                    std.mem.writeInt(T, int_bytes, val -% rng.int(T), endian);
                },
                .arithmetic_increase_32 => {
                    const T = u32;
                    if (input.items.len - index < @sizeOf(T)) continue;
                    const int_bytes = input.items[index..][0..@sizeOf(T)];
                    const val = std.mem.readInt(T, int_bytes, endian);
                    std.mem.writeInt(T, int_bytes, val +% rng.int(T), endian);
                },
                .arithmetic_decrease_32 => {
                    const T = u32;
                    if (input.items.len - index < @sizeOf(T)) continue;
                    const int_bytes = input.items[index..][0..@sizeOf(T)];
                    const val = std.mem.readInt(T, int_bytes, endian);
                    std.mem.writeInt(T, int_bytes, val -% rng.int(T), endian);
                },
                .random_value => {
                    // Prevent no-op by XOR-ing with 1-255
                    input.items[index] ^= 1 + rng.uintLessThanBiased(u8, 255);
                },
            }
        }
    }

    fn applyChunkMutations(gpa: Allocator, rng: std.Random, input: *std.ArrayListUnmanaged(u8), num_mutations: usize) Allocator.Error!void {
        for (0..num_mutations) |_| {
            const mutation, const index, const len = if (input.items.len > 0) m: {
                const rand = rng.uintLessThanBiased(usize, input.items.len * @typeInfo(ChunkMutation).Enum.fields.len);
                const mutation: ChunkMutation = @enumFromInt(rand / input.items.len);
                const index = rand % input.items.len;
                const len = @min(rng.int(u10), input.items.len - index);
                break :m .{ mutation, index, len };
            } else .{ .insert_bytes, 0, rng.int(u10) };

            switch (mutation) {
                .delete_bytes => {
                    std.mem.copyForwards(u8, input.items[index..], input.items[index + len ..]);
                    input.shrinkRetainingCapacity(input.items.len - len);
                },
                .clone_bytes => {
                    if (len == input.items.len) return;

                    const duped_start = rng.uintLessThanBiased(usize, input.items.len - len);
                    if (duped_start > index) {
                        std.mem.copyForwards(u8, input.items[index .. index + len], input.items[duped_start .. duped_start + len]);
                    } else {
                        std.mem.copyBackwards(u8, input.items[index .. index + len], input.items[duped_start .. duped_start + len]);
                    }
                },
                .insert_bytes => {
                    const new = try input.addManyAt(gpa, index, len);
                    rng.bytes(new);
                },
                .overwrite_bytes => {
                    rng.bytes(input.items[index .. index + len]);
                },
            }
        }
    }

    /// Update the statistics for the selected set of mutations and their
    /// resulting reward.
    pub fn update(h: *HavocMAB, reward: u1) void {
        const mutations = h.last_mutations.?;
        h.size_bandit.update(mutations.count_log2, reward);
        h.type_bandit[h.last_mutations.?.count_log2].update(@intFromEnum(mutations.type), reward);
    }
};

const Fuzzer = struct {
    gpa: Allocator,
    rng: std.Random.DefaultPrng,
    input: std.ArrayListUnmanaged(u8),
    pc_range: PcRange,
    count: usize,
    recent_cases: RunMap,
    deduplicated_runs: usize,
    coverage: Coverage,
    havoc: HavocMAB,
    last_case: ?*Run = null,

    const RunMap = std.ArrayHashMapUnmanaged(Run, void, Run.HashContext, false);

    const Coverage = struct {
        pc_table: std.AutoArrayHashMapUnmanaged(usize, void),
        run_id_hasher: std.hash.Wyhash,

        fn reset(cov: *Coverage) void {
            cov.pc_table.clearRetainingCapacity();
            cov.run_id_hasher = std.hash.Wyhash.init(0);
        }
    };

    const Run = struct {
        id: Id,
        input: []const u8,
        score: usize,

        const Id = u64;

        const HashContext = struct {
            pub fn eql(ctx: HashContext, a: Run, b: Run, b_index: usize) bool {
                _ = b_index;
                _ = ctx;
                return a.id == b.id;
            }
            pub fn hash(ctx: HashContext, a: Run) u32 {
                _ = ctx;
                return @truncate(a.id);
            }
        };

        fn deinit(run: *Run, gpa: Allocator) void {
            gpa.free(run.input);
            run.* = undefined;
        }
    };

    const Slice = extern struct {
        ptr: [*]const u8,
        len: usize,

        fn toZig(s: Slice) []const u8 {
            return s.ptr[0..s.len];
        }

        fn fromZig(s: []const u8) Slice {
            return .{
                .ptr = s.ptr,
                .len = s.len,
            };
        }
    };

    const PcRange = struct {
        start: usize,
        end: usize,
    };

    const Analysis = struct {
        score: usize,
        id: Run.Id,
    };

    fn analyzeLastRun(f: *Fuzzer) Analysis {
        const score = f.coverage.pc_table.count();
        const id = f.coverage.run_id_hasher.final();
        const reward = @intFromBool(score > f.last_case.?.score);
        f.havoc.update(reward);
        return .{
            .id = id,
            .score = score,
        };
    }

    fn next(f: *Fuzzer) ![]const u8 {
        const gpa = f.gpa;
        const rng = fuzzer.rng.random();

        if (f.recent_cases.entries.len == 0) {
            // Prepare initial input.
            try f.recent_cases.ensureUnusedCapacity(gpa, 100);
            const len = rng.uintLessThanBiased(usize, 80);
            try f.input.resize(gpa, len);
            rng.bytes(f.input.items);
            f.recent_cases.putAssumeCapacity(.{
                .id = 0,
                .input = try gpa.dupe(u8, f.input.items),
                .score = 0,
            }, {});
        } else {
            if (f.count % 1000 == 0) f.dumpStats();

            const analysis = f.analyzeLastRun();
            const gop = f.recent_cases.getOrPutAssumeCapacity(.{
                .id = analysis.id,
                .input = undefined,
                .score = undefined,
            });
            if (gop.found_existing) {
                //std.log.info("duplicate analysis: score={d} id={d}", .{ analysis.score, analysis.id });
                f.deduplicated_runs += 1;
                if (f.input.items.len < gop.key_ptr.input.len or gop.key_ptr.score == 0) {
                    gpa.free(gop.key_ptr.input);
                    gop.key_ptr.input = try gpa.dupe(u8, f.input.items);
                    gop.key_ptr.score = analysis.score;
                }
            } else {
                std.log.info("unique analysis: score={d} id={d}", .{ analysis.score, analysis.id });
                gop.key_ptr.* = .{
                    .id = analysis.id,
                    .input = try gpa.dupe(u8, f.input.items),
                    .score = analysis.score,
                };
            }

            if (f.recent_cases.entries.len >= 100) {
                const Context = struct {
                    values: []const Run,
                    pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                        return ctx.values[b_index].score < ctx.values[a_index].score;
                    }
                };
                f.recent_cases.sortUnstable(Context{ .values = f.recent_cases.keys() });
                const cap = 50;
                // This has to be done before deinitializing the deleted items.
                const doomed_runs = f.recent_cases.keys()[cap..];
                f.recent_cases.shrinkRetainingCapacity(cap);
                for (doomed_runs) |*run| {
                    std.log.info("culling score={d} id={d}", .{ run.score, run.id });
                    run.deinit(gpa);
                }
            }
        }

        const chosen_index = rng.uintLessThanBiased(usize, f.recent_cases.entries.len);
        f.last_case = &f.recent_cases.keys()[chosen_index];
        f.input.clearRetainingCapacity();
        f.input.appendSliceAssumeCapacity(f.last_case.?.input);
        try f.mutate();

        f.coverage.reset();
        f.count += 1;
        return f.input.items;
    }

    fn visitPc(f: *Fuzzer, pc: usize) void {
        errdefer |err| oom(err);
        try f.coverage.pc_table.put(f.gpa, pc, {});
        f.coverage.run_id_hasher.update(std.mem.asBytes(&pc));
    }

    fn dumpStats(f: *Fuzzer) void {
        std.log.info("stats: runs={d} deduplicated={d}", .{
            f.count,
            f.deduplicated_runs,
        });
        for (f.recent_cases.keys()[0..@min(f.recent_cases.entries.len, 5)], 0..) |run, i| {
            std.log.info("best[{d}] id={x} score={d} input: '{}'", .{
                i, run.id, run.score, std.zig.fmtEscapes(run.input),
            });
        }
        std.log.info(
            "HavocMAB size_stats={any}",
            .{&f.havoc.size_bandit.scores},
        );
        for (&f.havoc.type_bandit, 0..) |bandit, i| {
            std.log.info(
                "type_stats[2^{}]={any}",
                .{ i, &bandit.scores },
            );
        }
    }

    fn mutate(f: *Fuzzer) !void {
        const gpa = f.gpa;
        const rng = f.rng.random();

        if (f.input.items.len == 0) {
            const len = rng.uintLessThanBiased(usize, 80);
            try f.input.resize(gpa, len);
            rng.bytes(f.input.items);
            return;
        }

        try f.havoc.mutate(gpa, rng, &f.input);
    }
};

fn oom(err: anytype) noreturn {
    switch (err) {
        error.OutOfMemory => @panic("out of memory"),
    }
}

var general_purpose_allocator: std.heap.GeneralPurposeAllocator(.{}) = .{};

var fuzzer: Fuzzer = .{
    .gpa = general_purpose_allocator.allocator(),
    .rng = std.Random.DefaultPrng.init(0),
    .input = .{},
    .pc_range = .{ .start = 0, .end = 0 },
    .count = 0,
    .deduplicated_runs = 0,
    .recent_cases = .{},
    .coverage = undefined,
    .havoc = .{},
};

export fn fuzzer_next() Fuzzer.Slice {
    return Fuzzer.Slice.fromZig(fuzzer.next() catch |err| switch (err) {
        error.OutOfMemory => @panic("out of memory"),
    });
}
