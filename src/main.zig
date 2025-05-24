const std = @import("std");
const base64 = std.base64;
const time = std.time;
const atomic = std.atomic;
const Thread = std.Thread;
const sfmt = std.fmt;
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const meta = std.meta;
const heap = std.heap;
const process = std.process;
const crypto = std.crypto;
const builtin = @import("builtin");

const Md5 = crypto.hash.Md5;
const Sha1 = crypto.hash.Sha1;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const Sha512 = crypto.hash.sha2.Sha512;
const Sha3_512 = crypto.hash.sha3.Sha3_512;
const Blake3 = crypto.hash.Blake3;
const bcrypt = crypto.pwhash.bcrypt;

const HashTag = enum {
    md5,
    sha1,
    sha256,
    sha384,
    sha512,
    sha3_512,
    blake3,
    bcrypt,

    fn outLength(comptime self: HashTag) usize {
        return if (self == .bcrypt) 23 else self.Type().digest_length;
    }

    fn Type(comptime self: HashTag) type {
        return switch (self) {
            .md5 => Md5,
            .sha1 => Sha1,
            .sha256 => Sha256,
            .sha384 => Sha384,
            .sha512 => Sha512,
            .sha3_512 => Sha3_512,
            .blake3 => Blake3,
            .bcrypt => bcrypt,
        };
    }
};

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    process.exit(1);
}

const help =
    \\Usage: {s} [command] [options] [string]
    \\
    \\Commands:
    \\
    \\  help        Print this help and exit
    \\  md5         
    \\  sha1        
    \\  sha256      
    \\  sha384      
    \\  sha512      
    \\  sha3_512    
    \\  blake3      
    \\  bcrypt      
    \\
    \\Options
    \\
    \\  -l={{s}} (required) The path to password list
    \\  -t={{d}}            How many threads to use
    \\
    \\
;

pub fn main() !void {
    const gpa = heap.smp_allocator;
    const stdout = io.getStdOut().writer();

    var args: process.ArgIterator = try .initWithAllocator(gpa);
    const program = args.next() orelse "hasz";

    const arg0 = args.next() orelse {
        try stdout.print(help, .{program});
        fatal("expected a command", .{});
    };

    if (mem.eql(u8, arg0, "help")) {
        try stdout.print(help, .{program});
        return;
    }

    const hash_tag = meta.stringToEnum(HashTag, arg0) orelse {
        fatal("unexpected hash name '{s}'", .{arg0});
    };

    var m_in: ?[]const u8 = null;
    var m_list_path: ?[]const u8 = null;
    var m_thread_count: ?u32 = null;
    while (args.next()) |arg| {
        if (arg[0] != '-') {
            m_in = arg;
            break;
        }

        switch (arg[1]) {
            'l' => {
                if (arg[2] != '=') fatal("expected '=' after option", .{});
                m_list_path = arg[3..];
            },
            't' => {
                if (arg[2] != '=') fatal("expected '=' after option", .{});
                m_thread_count = try sfmt.parseInt(u32, arg[3..], 10);
            },
            else => fatal("unexpected option '{c}'", .{arg[1]}),
        }
    }

    if (args.next()) |arg| fatal("unexpected argument '{s}'", .{arg});
    var in = m_in orelse fatal("input argument not provided", .{});

    const list_path = m_list_path orelse {
        fatal("list file path not provided (-l)", .{});
    };

    try stdout.writeAll("\x1b[90;3mloading list file...\x1b[m");
    const bytes = try fs.cwd().readFileAlloc(gpa, list_path, 256_000_000);
    const entries = blk: {
        var entries: std.ArrayListUnmanaged([]const u8) = try .initCapacity(
            gpa,
            1 + bytes.len / 9,
        );

        var start: usize = 0;
        var i: usize = 0;
        while (i < bytes.len) : (i += 1) if (bytes[i] == '\n') {
            try entries.append(gpa, bytes[start..i]);
            start = i + 1;
        };

        if (i > start) try entries.append(gpa, bytes[start..i]);
        break :blk entries.items;
    };
    try stdout.writeAll("\x1b[2K\r");

    const thread_count = m_thread_count orelse try Thread.getCpuCount();

    var lock: Thread.RwLock = .{};
    var counter: atomic.Value(usize) = .init(0);
    var cracked: ?[]const u8 = null;

    var wait_group: Thread.WaitGroup = .{};
    wait_group.startMany(thread_count);

    switch (hash_tag) {
        .bcrypt => {
            const input_length = 60;
            if (in.len != input_length) {
                fatal("invalid input length for bcrypt (got {d}, expected {d})", .{
                    in.len,
                    input_length,
                });
            }

            const version = in[1..3];
            _ = version;

            const rounds_log = sfmt.parseInt(u6, in[4..6], 10) catch {
                fatal("invalid input", .{});
            };

            const decoder: base64.Base64Decoder = .init(
                "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".*,
                null,
            );

            var salt: [16]u8 = undefined;
            decoder.decode(&salt, in[7..29]) catch |err| {
                fatal("invalid input (salt {s})", .{@errorName(err)});
            };

            var password: [23]u8 = undefined;
            decoder.decode(&password, in[29..]) catch |err| {
                fatal("invalid input (password {s})", .{@errorName(err)});
            };

            var entry_i: usize = 0;
            var i: usize = 0;
            while (i < thread_count - 1) : (i += 1) {
                const len = (entries.len - entry_i) / (thread_count - i);

                const start = entry_i;
                entry_i += len;

                _ = try Thread.spawn(.{}, findHashBcrypt, .{
                    rounds_log,
                    salt,
                    password,
                    entries[start..entry_i],
                    &wait_group,
                    &lock,
                    &cracked,
                    &counter,
                });
            }

            _ = try Thread.spawn(.{}, findHashBcrypt, .{
                rounds_log,
                salt,
                password,
                entries[entry_i..],
                &wait_group,
                &lock,
                &cracked,
                &counter,
            });
        },
        inline else => |tag| {
            var hex_buf: [256]u8 = undefined;
            const hex_in = sfmt.hexToBytes(
                &hex_buf,
                in,
            ) catch fatal("input not in hex", .{});

            const input_length = tag.Type().digest_length;
            if (hex_in.len != input_length) {
                fatal("invalid input length for {s} (got {d}, expected {d})", .{
                    @tagName(tag),
                    hex_in.len,
                    input_length,
                });
            }

            var entry_i: usize = 0;
            var i: usize = 0;
            while (i < thread_count - 1) : (i += 1) {
                const len = (entries.len - entry_i) / (thread_count - i);

                const start = entry_i;
                entry_i += len;

                _ = try Thread.spawn(.{}, findHash, .{
                    tag,
                    hex_in,
                    entries[start..entry_i],
                    &wait_group,
                    &lock,
                    &cracked,
                    &counter,
                });
            }

            _ = try Thread.spawn(.{}, findHash, .{
                tag,
                hex_in,
                entries[entry_i..],
                &wait_group,
                &lock,
                &cracked,
                &counter,
            });
        },
    }

    _ = try Thread.spawn(.{}, progressBar, .{ &counter, entries.len, &cracked, &lock });

    const now: time.Instant = try .now();
    wait_group.wait();

    const c = cracked orelse {
        try stdout.writeAll("\x1b[2K\r\x1b[90;3mnot found\x1b[m");
        return;
    };

    try stdout.print("\x1b[2K\r\x1b[1m{s}\x1b[m ", .{c});

    const ms = (try time.Instant.now()).since(now) / time.ns_per_ms;
    if (ms < 1_000) try stdout.print("\x1b[90;3m{d} ms\x1b[m", .{ms}) else {
        const s = @as(f32, @floatFromInt(ms)) / time.ms_per_s;
        if (s < 60) try stdout.print("\x1b[90;3m{d:.2} s\x1b[m", .{s}) else {
            const min: u32 = @intFromFloat(s / 60);
            try stdout.print("\x1b[90;3m{d} m {d:.0} s\x1b[m", .{ min, @rem(s, 60) });
        }
    }
}

fn progressBar(
    counter: *atomic.Value(usize),
    entries_len: usize,
    cracked: *?[]const u8,
    lock: *Thread.RwLock,
) !void {
    var bw = io.bufferedWriter(io.getStdOut().writer());
    const writer = bw.writer();

    while (true) {
        defer Thread.sleep(10_000);

        {
            lock.lockShared();
            defer lock.unlockShared();

            if (cracked.* != null) break;
        }

        const count = counter.load(.monotonic);
        const progress =
            @as(f32, @floatFromInt(count)) / @as(f32, @floatFromInt(entries_len));

        try writer.writeAll("\x1b[2K\r");

        var i: usize = 0;
        const max = 10;
        const full_count: usize = @intFromFloat(progress * max);
        while (i < full_count) : (i += 1) {
            try writer.writeAll("█");
        }

        while (i < max) : (i += 1) {
            const char = if (i == max - 1) "▕" else " ";
            try writer.writeAll(char);
        }

        try writer.print(" \x1b[1m{d:.2}%\x1b[m ({d}/{d})", .{
            100 * progress,
            count,
            entries_len,
        });
        try bw.flush();
    }
}

fn findHashBcrypt(
    rounds_log: u6,
    salt: [16]u8,
    password: [23]u8,
    entries: []const []const u8,
    wait_group: *Thread.WaitGroup,
    lock: *Thread.RwLock,
    cracked: *?[]const u8,
    counter: *atomic.Value(usize),
) void {
    defer wait_group.finish();
    for (entries) |entry| {
        {
            lock.lockShared();
            defer lock.unlockShared();

            if (cracked.* != null) break;
        }

        const out = bcrypt.bcrypt(entry, salt, .{
            .rounds_log = rounds_log,
            .silently_truncate_password = false,
        });

        _ = counter.fetchAdd(1, .monotonic);
        if (mem.eql(u8, &password, &out)) {
            lock.lock();
            defer lock.unlock();

            cracked.* = entry;
            break;
        }
    }
}

fn findHash(
    comptime tag: HashTag,
    in: []const u8,
    entries: []const []const u8,
    wait_group: *Thread.WaitGroup,
    lock: *Thread.RwLock,
    cracked: *?[]const u8,
    counter: *atomic.Value(usize),
) void {
    defer wait_group.finish();
    for (entries) |entry| {
        {
            lock.lockShared();
            defer lock.unlockShared();

            if (cracked.* != null) break;
        }

        var out: [tag.outLength()]u8 = undefined;
        if (tag == .bcrypt) {
            const salt = in[4..20].*;
            const pass = in[20..];
            out = bcrypt.bcrypt(pass, salt, .owasp);
        } else {
            tag.Type().hash(entry, &out, .{});
        }

        _ = counter.fetchAdd(1, .monotonic);
        if (mem.eql(u8, out[0..in.len], in)) {
            lock.lock();
            defer lock.unlock();

            cracked.* = entry;
            break;
        }
    }
}
