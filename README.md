# nullsec-memcorrupt

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
      ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ░  ░  ░     ░   ░        
            ░                          ░    ░           ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░ M E M C O R R U P T ░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

![Zig](https://img.shields.io/badge/Zig-F7A41D?style=for-the-badge&logo=zig&logoColor=white)

## Overview

**nullsec-memcorrupt** is a memory corruption exploitation toolkit written in Zig. Leverages Zig's comptime features and memory safety controls for precise exploit development with zero runtime overhead.

## Features

- 🔴 **Heap Exploitation** - Use-after-free, double-free, heap overflow
- 📚 **Stack Attacks** - Buffer overflow, ROP chain builder
- 🎯 **Format Strings** - Automated format string exploitation
- 🔧 **Gadget Finder** - ROP/JOP gadget discovery
- 💉 **Shellcode Gen** - Position-independent code generation
- 🛡️ **Bypass Tools** - ASLR, NX, canary, RELRO defeat

## Requirements

- Zig 0.11+
- Linux x86_64 (primary target)
- GDB/LLDB (for debugging)

## Installation

```bash
git clone https://github.com/bad-antics/nullsec-memcorrupt.git
cd nullsec-memcorrupt
zig build -Drelease-fast
```

## Usage

```bash
# Find ROP gadgets
./memcorrupt gadgets -f ./vulnerable_binary

# Generate exploit template
./memcorrupt template -t stack_bof -o exploit.zig

# Analyze binary protections
./memcorrupt checksec -f ./binary

# Build ROP chain
./memcorrupt rop -f ./binary --goal execve

# Format string calculator
./memcorrupt fmtstr -offset 6 -target 0x404040 -value 0xdeadbeef
```

## Modules

| Module | Description |
|--------|-------------|
| `gadgets` | ROP/JOP gadget finder with semantic search |
| `template` | Exploit template generator |
| `checksec` | Binary protection analyzer |
| `rop` | Automated ROP chain builder |
| `fmtstr` | Format string exploit calculator |
| `heap` | Heap layout analyzer |
| `shellcode` | Shellcode generator and encoder |

## Disclaimer

For authorized security research and CTF competitions only. Unauthorized exploitation is illegal.

## License

NullSec Proprietary License

## Author

**bad-antics** - NullSec Security Team

---

*Part of the NullSec Security Toolkit*

---

[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=flat&logo=github&logoColor=white)](https://github.com/bad-antics)
[![Discord](https://img.shields.io/badge/Twitter-AnonAntics-1DA1F2?style=flat&logo=discord&logoColor=white)](https://x.com/AnonAntics)
