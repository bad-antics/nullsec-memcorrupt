// NullSec MemCorrupt - Hardened Memory Corruption Analysis Toolkit
// Language: Zig (Memory-Safe Systems Programming)
// Author: bad-antics
// License: NullSec Proprietary
// Security Level: Maximum Hardening
//
// This tool implements defense-in-depth principles:
// - Compile-time safety assertions
// - Runtime bounds checking
// - Secure memory allocation with canaries
// - Cryptographic memory wiping
// - Constant-time operations where applicable

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const io = std.io;
const fmt = std.fmt;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

// ============================================================================
// Security Constants - Compile-time Validated
// ============================================================================

const NULLSEC_VERSION: []const u8 = "2.0.0";
const MAX_GADGET_SIZE: usize = 32;
const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;
const ENTROPY_THRESHOLD: f64 = 7.0;
const CANARY_SIZE: usize = 16;
const MAX_GADGETS: usize = 10000;

comptime {
    std.debug.assert(MAX_GADGET_SIZE <= 64);
    std.debug.assert(CANARY_SIZE >= 8);
    std.debug.assert(MAX_FILE_SIZE <= 1024 * 1024 * 1024);
}

// ============================================================================
// Secure Banner
// ============================================================================

fn printBanner() void {
    const banner =
        \\
        \\    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
        \\    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
        \\   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
        \\   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
        \\   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
        \\   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
        \\   █░░░░░░░░░░░░░░ M E M C O R R U P T ░░░░░░░░░░░░░░░░░░░░░█
        \\   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
        \\                      bad-antics v
    ;
    std.debug.print("{s}{s}\n\n", .{ banner, NULLSEC_VERSION });
}

// ============================================================================
// Secure Memory Arena - Defense in Depth
// ============================================================================

const SecureArena = struct {
    backing: Allocator,
    canary: [CANARY_SIZE]u8,
    allocations: std.ArrayList(AllocationRecord),
    total_allocated: usize,
    max_allowed: usize,
    integrity_verified: bool,

    const AllocationRecord = struct {
        ptr: [*]u8,
        size: usize,
        timestamp: i64,
        checksum: u32,
        
        fn computeChecksum(data: []const u8) u32 {
            var hash: u32 = 0x811c9dc5;
            for (data) |byte| {
                hash ^= byte;
                hash *%= 0x01000193;
            }
            return hash;
        }
    };

    const Self = @This();

    pub fn init(backing: Allocator, max_alloc: usize) !Self {
        var canary: [CANARY_SIZE]u8 = undefined;
        crypto.random.bytes(&canary);

        return Self{
            .backing = backing,
            .canary = canary,
            .allocations = std.ArrayList(AllocationRecord).init(backing),
            .total_allocated = 0,
            .max_allowed = max_alloc,
            .integrity_verified = true,
        };
    }

    pub fn secureAlloc(self: *Self, size: usize) ![]u8 {
        const total = std.math.add(usize, size, CANARY_SIZE * 2) catch 
            return error.AllocationOverflow;
        
        if (self.total_allocated + total > self.max_allowed)
            return error.AllocationLimitExceeded;

        const raw = try self.backing.alloc(u8, total);
        
        @memcpy(raw[0..CANARY_SIZE], &self.canary);
        @memcpy(raw[total - CANARY_SIZE ..], &self.canary);
        @memset(raw[CANARY_SIZE .. total - CANARY_SIZE], 0);

        try self.allocations.append(.{
            .ptr = raw.ptr,
            .size = total,
            .timestamp = std.time.timestamp(),
            .checksum = AllocationRecord.computeChecksum(raw),
        });
        
        self.total_allocated += total;
        return raw[CANARY_SIZE .. total - CANARY_SIZE];
    }

    pub fn verifyIntegrity(self: *Self) bool {
        for (self.allocations.items) |record| {
            const slice = record.ptr[0..record.size];
            if (!mem.eql(u8, slice[0..CANARY_SIZE], &self.canary)) {
                self.integrity_verified = false;
                return false;
            }
            if (!mem.eql(u8, slice[record.size - CANARY_SIZE ..], &self.canary)) {
                self.integrity_verified = false;
                return false;
            }
        }
        return true;
    }

    pub fn secureWipe(self: *Self) void {
        for (self.allocations.items) |record| {
            crypto.utils.secureZero(u8, record.ptr[0..record.size]);
            self.backing.free(record.ptr[0..record.size]);
        }
        self.allocations.clearAndFree();
        crypto.utils.secureZero(u8, &self.canary);
        self.total_allocated = 0;
    }
};

// ============================================================================
// ELF Parser - Strict Validation & Bounds Checking
// ============================================================================

const ElfParser = struct {
    data: []const u8,
    header: ?Elf64Header = null,
    validated: bool = false,

    const ELF_MAGIC = [_]u8{ 0x7f, 'E', 'L', 'F' };
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;

    const Elf64Header = extern struct {
        e_ident: [16]u8,
        e_type: u16,
        e_machine: u16,
        e_version: u32,
        e_entry: u64,
        e_phoff: u64,
        e_shoff: u64,
        e_flags: u32,
        e_ehsize: u16,
        e_phentsize: u16,
        e_phnum: u16,
        e_shentsize: u16,
        e_shnum: u16,
        e_shstrndx: u16,
    };

    const Elf64Phdr = extern struct {
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_paddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_align: u64,
    };

    const Self = @This();

    pub fn init(data: []const u8) Self {
        return .{ .data = data };
    }

    pub fn validate(self: *Self) !void {
        if (self.data.len < @sizeOf(Elf64Header)) return error.FileTooSmall;
        if (self.data.len > MAX_FILE_SIZE) return error.FileTooLarge;
        if (!mem.eql(u8, self.data[0..4], &ELF_MAGIC)) return error.InvalidMagic;
        if (self.data[4] != ELFCLASS64) return error.Not64Bit;
        if (self.data[5] != ELFDATA2LSB) return error.NotLittleEndian;

        const hdr = @as(*const Elf64Header, @ptrCast(@alignCast(self.data.ptr)));
        
        // Validate all offsets before use
        if (hdr.e_phoff >= self.data.len) return error.InvalidPhoff;
        if (hdr.e_shoff >= self.data.len) return error.InvalidShoff;
        
        const ph_end = std.math.add(u64, hdr.e_phoff, 
            @as(u64, hdr.e_phnum) * @as(u64, hdr.e_phentsize)) catch 
                return error.Overflow;
        if (ph_end > self.data.len) return error.PhdrOverflow;

        self.header = hdr.*;
        self.validated = true;
    }

    pub fn getSecurityFeatures(self: *const Self) !SecurityFeatures {
        if (!self.validated) return error.NotValidated;
        
        var features = SecurityFeatures{};
        const hdr = self.header.?;

        features.pie = (hdr.e_type == 3); // ET_DYN

        var i: u16 = 0;
        while (i < hdr.e_phnum) : (i += 1) {
            const off = hdr.e_phoff + @as(u64, i) * @as(u64, hdr.e_phentsize);
            if (off + @sizeOf(Elf64Phdr) > self.data.len) continue;
            
            const ph = @as(*const Elf64Phdr, @ptrCast(@alignCast(self.data.ptr + off)));

            if (ph.p_type == 0x6474e551) features.nx = (ph.p_flags & 1) == 0;
            if (ph.p_type == 0x6474e552) features.relro = true;
            if ((ph.p_flags & 7) == 7) features.rwx_segments += 1;
        }

        features.canary = mem.indexOf(u8, self.data, "__stack_chk_fail") != null;
        features.fortify = mem.indexOf(u8, self.data, "__fortify_fail") != null;

        return features;
    }
};

const SecurityFeatures = struct {
    pie: bool = false,
    nx: bool = false,
    canary: bool = false,
    relro: bool = false,
    fortify: bool = false,
    rwx_segments: u32 = 0,

    pub fn display(self: *const SecurityFeatures) void {
        const G = "\x1b[32m✓\x1b[0m";
        const R = "\x1b[31m✗\x1b[0m";
        
        std.debug.print("\n[*] Binary Security Analysis\n", .{});
        std.debug.print("─────────────────────────────────────────\n", .{});
        std.debug.print("  PIE (ASLR):      {s}\n", .{if (self.pie) G else R});
        std.debug.print("  NX (DEP):        {s}\n", .{if (self.nx) G else R});
        std.debug.print("  Stack Canary:    {s}\n", .{if (self.canary) G else R});
        std.debug.print("  RELRO:           {s}\n", .{if (self.relro) G else R});
        std.debug.print("  FORTIFY_SOURCE:  {s}\n", .{if (self.fortify) G else R});
        
        if (self.rwx_segments > 0) {
            std.debug.print("  \x1b[31m⚠ {d} RWX segment(s) - DANGEROUS\x1b[0m\n", .{self.rwx_segments});
        }
    }
};

// ============================================================================
// ROP Gadget Finder - Pattern Matching Engine
// ============================================================================

const GadgetFinder = struct {
    data: []const u8,
    base: u64,
    gadgets: std.ArrayList(Gadget),

    const Gadget = struct {
        addr: u64,
        bytes: [MAX_GADGET_SIZE]u8,
        len: usize,
        name: []const u8,
        score: u8,
    };

    const Pattern = struct { 
        bytes: []const u8, 
        mask: []const u8, 
        name: []const u8, 
        score: u8 
    };

    const patterns = [_]Pattern{
        .{ .bytes = &.{0xc3}, .mask = &.{0xff}, .name = "ret", .score = 5 },
        .{ .bytes = &.{ 0x5f, 0xc3 }, .mask = &.{ 0xff, 0xff }, .name = "pop rdi; ret", .score = 5 },
        .{ .bytes = &.{ 0x5e, 0xc3 }, .mask = &.{ 0xff, 0xff }, .name = "pop rsi; ret", .score = 5 },
        .{ .bytes = &.{ 0x5a, 0xc3 }, .mask = &.{ 0xff, 0xff }, .name = "pop rdx; ret", .score = 5 },
        .{ .bytes = &.{ 0x58, 0xc3 }, .mask = &.{ 0xff, 0xff }, .name = "pop rax; ret", .score = 5 },
        .{ .bytes = &.{ 0x59, 0xc3 }, .mask = &.{ 0xff, 0xff }, .name = "pop rcx; ret", .score = 4 },
        .{ .bytes = &.{ 0x0f, 0x05, 0xc3 }, .mask = &.{ 0xff, 0xff, 0xff }, .name = "syscall; ret", .score = 5 },
        .{ .bytes = &.{ 0xc9, 0xc3 }, .mask = &.{ 0xff, 0xff }, .name = "leave; ret", .score = 4 },
        .{ .bytes = &.{ 0x48, 0x89, 0xc7, 0xc3 }, .mask = &.{ 0xff, 0xff, 0xff, 0xff }, .name = "mov rdi, rax; ret", .score = 4 },
        .{ .bytes = &.{ 0x48, 0x31, 0xc0, 0xc3 }, .mask = &.{ 0xff, 0xff, 0xff, 0xff }, .name = "xor rax, rax; ret", .score = 4 },
        .{ .bytes = &.{ 0x41, 0x5f, 0xc3 }, .mask = &.{ 0xff, 0xff, 0xff }, .name = "pop r15; ret", .score = 3 },
        .{ .bytes = &.{ 0x41, 0x5e, 0xc3 }, .mask = &.{ 0xff, 0xff, 0xff }, .name = "pop r14; ret", .score = 3 },
    };

    const Self = @This();

    pub fn init(alloc: Allocator, data: []const u8, base: u64) Self {
        return .{
            .data = data,
            .base = base,
            .gadgets = std.ArrayList(Gadget).init(alloc),
        };
    }

    pub fn scan(self: *Self) !void {
        for (patterns) |p| {
            if (p.bytes.len > self.data.len) continue;
            
            var off: usize = 0;
            while (off <= self.data.len - p.bytes.len) : (off += 1) {
                if (self.matchPattern(off, p)) {
                    if (self.gadgets.items.len >= MAX_GADGETS) return;
                    
                    var g = Gadget{
                        .addr = self.base + off,
                        .bytes = undefined,
                        .len = p.bytes.len,
                        .name = p.name,
                        .score = p.score,
                    };
                    @memcpy(g.bytes[0..p.bytes.len], self.data[off..][0..p.bytes.len]);
                    try self.gadgets.append(g);
                }
            }
        }
        
        std.mem.sort(Gadget, self.gadgets.items, {}, struct {
            fn cmp(_: void, a: Gadget, b: Gadget) bool {
                return a.score > b.score;
            }
        }.cmp);
    }

    fn matchPattern(self: *const Self, off: usize, p: Pattern) bool {
        for (p.bytes, p.mask, 0..) |b, m, i| {
            if ((self.data[off + i] & m) != (b & m)) return false;
        }
        return true;
    }

    pub fn display(self: *const Self, limit: usize) void {
        const stars = [_][]const u8{ "☆☆☆☆☆", "★☆☆☆☆", "★★☆☆☆", "★★★☆☆", "★★★★☆", "★★★★★" };
        
        std.debug.print("\n[*] ROP Gadgets: {d} found\n", .{self.gadgets.items.len});
        std.debug.print("─────────────────────────────────────────────────\n", .{});
        
        for (self.gadgets.items[0..@min(limit, self.gadgets.items.len)]) |g| {
            std.debug.print("  0x{x:0>12}: {s:<24} {s}\n", .{
                g.addr,
                g.name,
                stars[@min(g.score, 5)],
            });
        }
    }

    pub fn deinit(self: *Self) void {
        self.gadgets.deinit();
    }
};

// ============================================================================
// Shellcode Encoder - XOR with Bad Character Avoidance
// ============================================================================

const ShellcodeEncoder = struct {
    bad_chars: []const u8,
    
    const Self = @This();

    pub fn init(bad: []const u8) Self {
        return .{ .bad_chars = bad };
    }

    pub fn xorEncode(self: *const Self, alloc: Allocator, sc: []const u8) !EncodedResult {
        var key: u8 = 0;
        
        key_search: for (1..256) |k| {
            const test_key: u8 = @intCast(k);
            if (self.hasBad(&.{test_key})) continue;
            
            for (sc) |b| {
                if (self.hasBad(&.{b ^ test_key})) continue :key_search;
            }
            key = test_key;
            break;
        }
        
        if (key == 0) return error.NoValidKey;

        const encoded = try alloc.alloc(u8, sc.len);
        for (sc, 0..) |b, i| encoded[i] = b ^ key;

        return .{
            .data = encoded,
            .key = key,
            .orig_entropy = calcEntropy(sc),
            .enc_entropy = calcEntropy(encoded),
        };
    }

    fn hasBad(self: *const Self, data: []const u8) bool {
        for (data) |b| {
            for (self.bad_chars) |bad| {
                if (b == bad) return true;
            }
        }
        return false;
    }

    fn calcEntropy(data: []const u8) f64 {
        if (data.len == 0) return 0;
        
        var freq = [_]u64{0} ** 256;
        for (data) |b| freq[b] += 1;
        
        var ent: f64 = 0;
        const len: f64 = @floatFromInt(data.len);
        
        for (freq) |f| {
            if (f > 0) {
                const p: f64 = @as(f64, @floatFromInt(f)) / len;
                ent -= p * @log2(p);
            }
        }
        return ent;
    }
};

const EncodedResult = struct {
    data: []u8,
    key: u8,
    orig_entropy: f64,
    enc_entropy: f64,

    pub fn display(self: *const EncodedResult) void {
        std.debug.print("\n[*] Encoded Shellcode\n", .{});
        std.debug.print("─────────────────────────────────────────\n", .{});
        std.debug.print("  XOR Key:         0x{x:0>2}\n", .{self.key});
        std.debug.print("  Size:            {d} bytes\n", .{self.data.len});
        std.debug.print("  Orig Entropy:    {d:.4} bits/byte\n", .{self.orig_entropy});
        std.debug.print("  Enc Entropy:     {d:.4} bits/byte\n", .{self.enc_entropy});
        
        if (self.enc_entropy > ENTROPY_THRESHOLD) {
            std.debug.print("  \x1b[33m⚠ High entropy - may trigger heuristics\x1b[0m\n", .{});
        }
        
        std.debug.print("\n  Encoded bytes:\n  ", .{});
        for (self.data, 0..) |b, i| {
            std.debug.print("\\x{x:0>2}", .{b});
            if ((i + 1) % 16 == 0 and i + 1 < self.data.len) std.debug.print("\n  ", .{});
        }
        std.debug.print("\n", .{});
    }
};

// ============================================================================
// Format String Calculator
// ============================================================================

const FmtStrCalc = struct {
    target: u64,
    value: u64,
    offset: u32,

    pub fn calculate(self: *const FmtStrCalc) void {
        std.debug.print("\n[*] Format String Payload\n", .{});
        std.debug.print("─────────────────────────────────────────\n", .{});
        std.debug.print("  Target:    0x{x:0>16}\n", .{self.target});
        std.debug.print("  Value:     0x{x:0>16}\n", .{self.value});
        std.debug.print("  Offset:    {d}\n", .{self.offset});
        
        std.debug.print("\n  Byte-by-byte (%hhn):\n", .{});
        
        var written: u64 = 0;
        for (0..8) |i| {
            const byte_val = (self.value >> (@as(u6, @intCast(i)) * 8)) & 0xff;
            const pad = if (byte_val >= written) byte_val - written else 256 + byte_val - written;
            written = (written + pad) & 0xff;
            std.debug.print("    [byte {d}]: %{d}c%{d}$hhn\n", .{ i, pad, self.offset + @as(u32, @intCast(i)) });
        }
    }
};

// ============================================================================
// Main Entry Point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    printBanner();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const cmd = args[1];

    if (mem.eql(u8, cmd, "checksec") and args.len >= 3) {
        try checksecCmd(args[2]);
    } else if (mem.eql(u8, cmd, "gadgets") and args.len >= 3) {
        try gadgetsCmd(alloc, args[2]);
    } else if (mem.eql(u8, cmd, "encode") and args.len >= 3) {
        try encodeCmd(alloc, args[2]);
    } else if (mem.eql(u8, cmd, "fmtstr") and args.len >= 4) {
        try fmtstrCmd(args);
    } else {
        printUsage();
    }
}

fn printUsage() void {
    std.debug.print(
        \\USAGE:
        \\    memcorrupt <command> [options]
        \\
        \\COMMANDS:
        \\    checksec <binary>           Analyze binary protections
        \\    gadgets <binary>            Find ROP gadgets  
        \\    encode <shellcode_hex>      XOR encode shellcode
        \\    fmtstr <addr> <value>       Format string calculator
        \\
        \\EXAMPLES:
        \\    memcorrupt checksec /bin/ls
        \\    memcorrupt gadgets ./vulnerable
        \\    memcorrupt encode 4831c050...
        \\    memcorrupt fmtstr 0x601020 0x4141414141414141
        \\
    , .{});
}

fn checksecCmd(path: []const u8) !void {
    std.debug.print("[*] Analyzing: {s}\n", .{path});
    
    const file = fs.cwd().openFile(path, .{}) catch |e| {
        std.debug.print("[!] Error: {}\n", .{e});
        return;
    };
    defer file.close();

    const stat = try file.stat();
    if (stat.size > MAX_FILE_SIZE) {
        std.debug.print("[!] File too large\n", .{});
        return;
    }

    var buf: [MAX_FILE_SIZE]u8 = undefined;
    const n = try file.readAll(&buf);

    var parser = ElfParser.init(buf[0..n]);
    try parser.validate();
    
    const features = try parser.getSecurityFeatures();
    features.display();
}

fn gadgetsCmd(alloc: Allocator, path: []const u8) !void {
    std.debug.print("[*] Scanning: {s}\n", .{path});
    
    const file = fs.cwd().openFile(path, .{}) catch |e| {
        std.debug.print("[!] Error: {}\n", .{e});
        return;
    };
    defer file.close();

    var buf: [MAX_FILE_SIZE]u8 = undefined;
    const n = try file.readAll(&buf);

    var finder = GadgetFinder.init(alloc, buf[0..n], 0x400000);
    defer finder.deinit();
    
    try finder.scan();
    finder.display(50);
}

fn encodeCmd(alloc: Allocator, hex: []const u8) !void {
    if (hex.len % 2 != 0) {
        std.debug.print("[!] Invalid hex length\n", .{});
        return;
    }

    const sc = try alloc.alloc(u8, hex.len / 2);
    defer alloc.free(sc);

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        sc[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch {
            std.debug.print("[!] Invalid hex at {d}\n", .{i});
            return;
        };
    }

    const bad = &[_]u8{ 0x00, 0x0a, 0x0d };
    const encoder = ShellcodeEncoder.init(bad);
    
    const result = try encoder.xorEncode(alloc, sc);
    defer alloc.free(result.data);
    
    result.display();
}

fn fmtstrCmd(args: [][]u8) !void {
    const target = std.fmt.parseInt(u64, args[2], 0) catch {
        std.debug.print("[!] Invalid target\n", .{});
        return;
    };
    
    const value = std.fmt.parseInt(u64, args[3], 0) catch {
        std.debug.print("[!] Invalid value\n", .{});
        return;
    };
    
    const offset: u32 = if (args.len > 4) 
        std.fmt.parseInt(u32, args[4], 10) catch 6 
    else 6;

    const calc = FmtStrCalc{ .target = target, .value = value, .offset = offset };
    calc.calculate();
}
