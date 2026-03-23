# trace-cli

AI-first ARM64 trace analysis tool. Designed for AI agents (Claude Code) to efficiently analyze unidbg execution traces.

> Fork of [trace-ui](https://github.com/anthropics/trace-ui), rebuilt from scratch with an AI-product mindset: the tool hides all complexity (indexing, caching, parsing) and exposes only the capabilities AI needs.

## Design Philosophy

- **AI is the explorer, human is the decision-maker** — tool provides capabilities, not interpretations
- **One bite at a time** — each command returns ≤50 lines, sized for LLM context windows
- **Zero ceremony** — no sessions, no setup, no index commands. Just query, get results
- **Auto-everything** — first call auto-indexes (cached for subsequent calls)

## Commands

```bash
# Basic info (3 lines: file, line count, function count)
trace-cli <file> info

# Read instructions with register values and memory annotations
trace-cli <file> lines 100-150

# Search for patterns (replaces grep with trace awareness)
trace-cli <file> search "0x67452301"
trace-cli <file> search "eor " --range 3000-6000

# Backward taint analysis (the killer feature grep can't do)
trace-cli <file> taint x0@last --data-only
trace-cli <file> taint x0@5930 --data-only --range 3000-6000

# Reconstruct memory state at any point (extract keys, constants, tables)
trace-cli <file> memdump 0x123d6070 64 --at 730000

# Memory cross-references (who reads/writes this address)
trace-cli <file> xref 0x123df18c
```

## What Each Command Does

| Command | AI's Question | What It Returns |
|---------|--------------|-----------------|
| `info` | "What is this trace?" | Module name, line count, function count |
| `lines` | "Show me these instructions" | Raw trace lines with registers + memory annotations |
| `search` | "Find this pattern" | Matching lines with seq numbers (≤30 results) |
| `taint` | "Where does this value come from?" | Instructions in the backward dependency chain (≤50 lines) |
| `memdump` | "What's in memory here?" | Hexdump of memory state reconstructed from write history |
| `xref` | "Who accesses this address?" | All reads/writes to the address (≤30 results) |

## Taint Flags

| Flag | Effect |
|------|--------|
| `--data-only` | Cut control flow dependencies. Reduces noise from ~26% to ~0.14% of lines |
| `--range START-END` | Only show tainted lines within seq range |

## Real-World Validation

Tested on XiaoHongShu's `libxyass.so` shield algorithm (139K lines, heavily obfuscated):

- `search` located HMAC ipad/opad (`0x36`/`0x5c`), MD5 IV, bswap operations in seconds
- `taint --data-only` traced HMAC data flow: 36,974 → 199 tainted lines
- `memdump` extracted the full 64-byte HMAC key from AES-CBC decryption output
- `search "rev "` revealed the complete package header format (mode, appId, version, lengths)
- Total: algorithm structure (HMAC-MD5 → RC4 → Base64) identified in ~10 CLI calls

## unidbg Integration

This tool requires enhanced trace output from unidbg with memory address annotations. The modifications to unidbg's `AssemblyCodeDumper.java` and `RegAccessPrinter.java` add:

- `; mem[READ/WRITE] abs=0x...` — absolute memory addresses for all load/store instructions
- `data[0xADDR]=0xHEX` — delayed memory reads for SIMD stores (workaround for `reg_read_vector` returning stale values in CodeHook context)
- Q/D/S register value output in `RegAccessPrinter`

See the parent [unidbg-mcp](https://github.com/anthropics/unidbg-mcp) repo for the modified unidbg.

## Build

```bash
# Requires Rust 1.75+
cargo build --release

# Binary at target/release/trace-cli
```

## Architecture

```
trace file (mmap, zero-copy)
    │
    ▼
auto-index on first call (parallel scan, cached to disk)
    │
    ▼
6 commands → structured text output → AI agent
```

Core algorithms carried over from trace-ui:
- ARM64 instruction parser (unidbg format)
- DEF-USE data flow analysis
- Backward taint slicing (BFS on dependency graph)
- Call tree builder (BL/BLR/RET matching)
- Memory access index
- Register checkpoints (every 1000 lines)
- Line index (sampled every 256 lines for O(1) random access)
- Disk cache with SHA-256 validation

## License

[Personal Use License](LICENSE)
