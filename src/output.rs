use anyhow::{bail, Result};

use crate::core::slicer::bfs_slice_with_options;
use crate::core::types::parse_reg;
use crate::session::Session;

const MAX_LINES: usize = 50;

/// Extract the module name from the first instruction line.
/// Looks for `][module.so 0x...]` pattern in unidbg format:
/// `[07:17:13 488][libtiny.so 0x174250] ...`
fn extract_module_name(data: &[u8]) -> String {
    // Search the first few KB for the pattern "][" followed by module name
    let search_end = data.len().min(4096);
    let haystack = std::str::from_utf8(&data[..search_end]).unwrap_or("");
    // Find "][" which marks the boundary between timestamp and module sections
    if let Some(pos) = haystack.find("][") {
        let inner = &haystack[pos + 2..]; // skip "]["
        // Module name ends at space: "libtiny.so 0x..."
        if let Some(space) = inner.find(' ') {
            return inner[..space].to_string();
        }
    }
    "unknown".to_string()
}

pub fn print_lines(session: &Session, start: u32, end: u32) {
    let data: &[u8] = &session.mmap;
    let view = session.line_index_view();
    let total = end.saturating_sub(start) + 1;
    let show = total.min(MAX_LINES as u32);

    if total > MAX_LINES as u32 {
        println!("showing first {} of {} requested lines", MAX_LINES, total);
        println!();
    }

    for seq in start..start + show {
        if let Some(line_bytes) = view.get_line(data, seq) {
            let line = String::from_utf8_lossy(line_bytes);
            println!("[{}] {}", seq, line);
        }
    }
}

pub fn print_taint(session: &Session, spec: &str, range: Option<&str>, addr: Option<&str>, data_only: bool, ignore_sp: bool) -> Result<()> {
    // Parse range if provided: "START-END"
    let (range_start, range_end) = if let Some(r) = range {
        let parts: Vec<&str> = r.splitn(2, '-').collect();
        if parts.len() != 2 {
            bail!("invalid range '{}': expected format 'START-END' (e.g. 3000-6000)", r);
        }
        let s: u32 = parts[0].parse()
            .map_err(|_| anyhow::anyhow!("invalid range start: {}", parts[0]))?;
        let e: u32 = parts[1].parse()
            .map_err(|_| anyhow::anyhow!("invalid range end: {}", parts[1]))?;
        (Some(s), Some(e))
    } else {
        (None, None)
    };

    // Parse addr range if provided: "0xSTART-0xEND"
    let addr_filter = addr.and_then(parse_addr_range);

    // Parse spec: "x0@last" or "x0@5000"
    let parts: Vec<&str> = spec.splitn(2, '@').collect();
    if parts.len() != 2 {
        bail!("invalid spec '{}': expected format 'REG@POSITION' (e.g. x0@last, x0@5000)", spec);
    }

    let reg_name = parts[0];
    let position = parts[1];

    let reg_id = parse_reg(reg_name)
        .ok_or_else(|| anyhow::anyhow!("unknown register: {}", reg_name))?;

    // Resolve the starting line index
    let start_index = if position == "last" {
        // Use reg_last_def to find the last definition
        let raw = session.reg_last_def.get(&reg_id)
            .ok_or_else(|| anyhow::anyhow!("register {} has no definition in trace", reg_name))?;
        *raw
    } else {
        // Parse as a line number, use that directly
        let target_seq: u32 = position.parse()
            .map_err(|_| anyhow::anyhow!("invalid position '{}': expected 'last' or a line number", position))?;

        // The user wants to slice from reg at a specific line.
        // We need to find where reg was last defined at or before target_seq.
        // Scan backward using reg_last_def won't work since it only has the final state.
        // For simplicity, we just use target_seq as the start line directly.
        // The user presumably knows that the register is defined at that line.
        target_seq
    };

    let scan_view = session.scan_view();
    let marked = bfs_slice_with_options(&scan_view, &[start_index], data_only);
    let total_marked = marked.count_ones();

    // Count tainted in range if --range is specified
    let (tainted_in_range, header_suffix) = if let (Some(rs), Some(re)) = (range_start, range_end) {
        let count = marked.iter().enumerate()
            .filter(|(i, is_set)| **is_set && (*i as u32) >= rs && (*i as u32) <= re)
            .count();
        (count, format!("  (showing seq {}-{})  ({} tainted in range / {} total tainted / {} lines)",
                        rs, re, count, total_marked, session.total_lines))
    } else {
        (total_marked, format!("  ({} tainted lines / {} total)", total_marked, session.total_lines))
    };

    let flags_str = {
        let mut f = Vec::new();
        if data_only { f.push("data-only"); }
        if ignore_sp { f.push("ignore-sp"); }
        if f.is_empty() { String::new() } else { format!("  [{}]", f.join(", ")) }
    };

    println!("Taint: {} @ line {}{}{}",
             reg_name, start_index & 0x1FFFFFFF, header_suffix, flags_str);
    println!();

    let data: &[u8] = &session.mmap;
    let view = session.line_index_view();
    let mut printed = 0usize;
    let mut skipped_sp = 0usize;
    let effective_total = tainted_in_range;

    for (i, is_set) in marked.iter().enumerate() {
        if !*is_set {
            continue;
        }
        // Apply --range filter
        if let Some(rs) = range_start {
            if (i as u32) < rs {
                continue;
            }
        }
        if let Some(re) = range_end {
            if (i as u32) > re {
                continue;
            }
        }
        if let Some(line_bytes) = view.get_line(data, i as u32) {
            let line = String::from_utf8_lossy(line_bytes);

            // Apply --addr filter
            if let Some((addr_lo, addr_hi)) = addr_filter {
                if let Some(offset) = extract_so_offset(&line) {
                    if offset < addr_lo || offset > addr_hi {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // Apply --ignore-sp filter
            if ignore_sp && is_sp_fp_only_line(&line) {
                skipped_sp += 1;
                continue;
            }

            if printed >= MAX_LINES {
                let remaining = effective_total - printed - skipped_sp;
                println!("... {} more tainted lines ({}/{})", remaining, effective_total, session.total_lines);
                break;
            }
            println!("[{}] {}", i, line);
            printed += 1;
        }
    }

    if ignore_sp && skipped_sp > 0 {
        println!();
        println!("({} SP/FP-only lines filtered by --ignore-sp)", skipped_sp);
    }

    Ok(())
}

/// Check if a tainted line only modifies SP and/or FP (x29) registers.
/// Looks at the "=> " section and checks if the only register assignments are
/// sp= and/or fp=/x29=.
fn is_sp_fp_only_line(line: &str) -> bool {
    // Find the "=> " section which shows register outputs
    let arrow_pos = match line.rfind("=> ") {
        Some(pos) => pos,
        None => return false,
    };
    let after_arrow = &line[arrow_pos + 3..];

    // Extract register assignments: patterns like "reg=value"
    // If there are no register assignments at all, don't filter
    let mut has_any_reg = false;
    let mut has_non_sp_fp = false;

    for token in after_arrow.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let reg = &token[..eq_pos];
            has_any_reg = true;
            // sp, fp, x29, w29 are considered SP/FP registers
            match reg {
                "sp" | "fp" | "x29" | "w29" => {}
                _ => {
                    has_non_sp_fp = true;
                    break;
                }
            }
        }
    }

    has_any_reg && !has_non_sp_fp
}

/// Extract SO offset from a trace line.
/// Trace format: `[timestamp][libtiny.so 0xOFFSET] [opcode] ...`
/// Returns the hex offset (e.g. 0x243d38) or None if not found.
fn extract_so_offset(line: &str) -> Option<u64> {
    // Find the second '[' which starts the module bracket: "][libtiny.so 0xOFFSET]"
    let first_close = line.find(']')?;
    let rest = &line[first_close + 1..];
    // rest starts with "[libtiny.so 0x..."
    if !rest.starts_with('[') { return None; }
    let inner_end = rest.find(']')?;
    let bracket_content = &rest[1..inner_end]; // "libtiny.so 0x243d38"
    let hex_start = bracket_content.find(" 0x")?;
    let hex_str = &bracket_content[hex_start + 3..];
    u64::from_str_radix(hex_str, 16).ok()
}

/// Parse an addr range like "0x246F00-0x249800" into (start, end).
fn parse_addr_range(addr_range: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = addr_range.splitn(2, '-').collect();
    if parts.len() != 2 { return None; }
    let start_clean = parts[0].strip_prefix("0x").or_else(|| parts[0].strip_prefix("0X")).unwrap_or(parts[0]);
    let end_clean = parts[1].strip_prefix("0x").or_else(|| parts[1].strip_prefix("0X")).unwrap_or(parts[1]);
    let start = u64::from_str_radix(start_clean, 16).ok()?;
    let end = u64::from_str_radix(end_clean, 16).ok()?;
    Some((start, end))
}

pub fn print_info(session: &Session) {
    let data: &[u8] = &session.mmap;
    let module_name = extract_module_name(data);

    // Entry address from root node (nodes[0])
    let entry_addr = session.call_tree.nodes[0].func_addr;

    // Function count: all nodes except root (root is the implicit entry)
    let func_count = session.call_tree.nodes.len();

    println!("Trace: {}  {} lines  unidbg", module_name, session.total_lines);
    println!("Entry: 0x{:x}", entry_addr);
    println!("Functions: {}", func_count);
}

const MAX_SEARCH_RESULTS: usize = 30;

pub fn print_search(session: &Session, pattern: &str, range: Option<&str>, addr: Option<&str>) {
    // Parse range if provided: "START-END"
    let (range_start, range_end) = if let Some(r) = range {
        let parts: Vec<&str> = r.splitn(2, '-').collect();
        if parts.len() == 2 {
            let s: u32 = parts[0].parse().unwrap_or(0);
            let e: u32 = parts[1].parse().unwrap_or(u32::MAX);
            (s, e)
        } else {
            (0, session.total_lines.saturating_sub(1))
        }
    } else {
        (0, session.total_lines.saturating_sub(1))
    };

    // Parse addr range if provided: "0xSTART-0xEND"
    let addr_filter = addr.and_then(parse_addr_range);

    let data: &[u8] = &session.mmap;
    let view = session.line_index_view();
    let pattern_lower = pattern.to_ascii_lowercase();

    let mut matches: Vec<(u32, String)> = Vec::new();
    let mut total_matches: usize = 0;

    for seq in range_start..=range_end {
        if let Some(line_bytes) = view.get_line(data, seq) {
            let line = String::from_utf8_lossy(line_bytes);
            if line.to_ascii_lowercase().contains(&pattern_lower) {
                // Apply addr filter
                if let Some((addr_lo, addr_hi)) = addr_filter {
                    if let Some(offset) = extract_so_offset(&line) {
                        if offset < addr_lo || offset > addr_hi {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                total_matches += 1;
                if matches.len() < MAX_SEARCH_RESULTS {
                    matches.push((seq, line.into_owned()));
                }
            }
        }
    }

    let range_suffix = if range.is_some() {
        format!("  (seq {}-{})", range_start, range_end)
    } else {
        String::new()
    };
    let addr_suffix = if let Some(a) = addr {
        format!("  (addr {})", a)
    } else {
        String::new()
    };

    println!("Search: \"{}\"  {} matches{}{}", pattern, total_matches, range_suffix, addr_suffix);
    println!();

    for (seq, line) in &matches {
        println!("[{}] {}", seq, line);
    }

    if total_matches > MAX_SEARCH_RESULTS {
        println!("... {} more matches", total_matches - MAX_SEARCH_RESULTS);
    }
}

const MAX_XREF_RESULTS: usize = 30;

pub fn print_xref(session: &Session, addr_str: &str) -> Result<()> {
    // Parse hex address: accept "0x123e7024" or "123e7024"
    let addr_clean = addr_str.strip_prefix("0x").unwrap_or(addr_str);
    let addr = u64::from_str_radix(addr_clean, 16)
        .map_err(|_| anyhow::anyhow!("invalid hex address: {}", addr_str))?;

    let mem_view = session.mem_accesses_view();

    match mem_view.query(addr) {
        Some(records) => {
            println!("Xref: 0x{:x}  {} accesses", addr, records.len());
            println!();

            let data: &[u8] = &session.mmap;
            let line_view = session.line_index_view();

            for (i, rec) in records.iter().enumerate() {
                if i >= MAX_XREF_RESULTS {
                    println!("... {} more accesses", records.len() - MAX_XREF_RESULTS);
                    break;
                }
                let rw_str = if rec.is_read() { "READ " } else { "WRITE" };
                let line_text = line_view.get_line(data, rec.seq)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_else(|| "<no line>".to_string());
                println!("[{}] {}  {}  value=0x{:x}", rec.seq, rw_str, line_text, rec.data);
            }
        }
        None => {
            println!("Xref: 0x{:x}  0 accesses", addr);
            println!();
            println!("(no memory accesses found for this address)");
        }
    }

    Ok(())
}

const MAX_MEMDUMP_SIZE: usize = 256;

/// Extract module base address from the first trace line.
/// Line format: `[...][libtiny.so 0xOFFSET] [...] 0xABSOLUTE: "..."`
/// module_base = ABSOLUTE - OFFSET
fn extract_module_base(data: &[u8]) -> Option<u64> {
    let search_end = data.len().min(4096);
    let haystack = std::str::from_utf8(&data[..search_end]).ok()?;
    // Find SO offset from [module 0xOFFSET]
    let bracket_start = haystack.find("][")?;
    let inner = &haystack[bracket_start + 2..];
    let bracket_end = inner.find(']')?;
    let bracket_content = &inner[..bracket_end];
    let hex_pos = bracket_content.find(" 0x")?;
    let offset_str = &bracket_content[hex_pos + 3..];
    let so_offset = u64::from_str_radix(offset_str, 16).ok()?;
    // Find absolute address: "0xABSOLUTE:"
    let after_bracket = &inner[bracket_end + 1..];
    // Skip opcode bracket: " [hexcode] 0xABSOLUTE:"
    let abs_marker = after_bracket.find("] 0x")?;
    let abs_start = &after_bracket[abs_marker + 4..];
    let abs_end = abs_start.find(':')?;
    let abs_addr = u64::from_str_radix(&abs_start[..abs_end], 16).ok()?;
    Some(abs_addr - so_offset)
}

pub fn print_calls(session: &Session, func_str: &str) -> Result<()> {
    let func_clean = func_str.strip_prefix("0x").or_else(|| func_str.strip_prefix("0X")).unwrap_or(func_str);
    let func_offset = u64::from_str_radix(func_clean, 16)
        .map_err(|_| anyhow::anyhow!("invalid hex address: {}", func_str))?;

    let data: &[u8] = &session.mmap;
    let module_base = extract_module_base(data)
        .ok_or_else(|| anyhow::anyhow!("cannot determine module base from trace"))?;
    let func_abs = module_base + func_offset;

    let line_view = session.line_index_view();

    // Find all CallTree nodes matching this func_addr
    let mut calls: Vec<&crate::core::call_tree::CallTreeNode> = session.call_tree.nodes.iter()
        .filter(|n| n.func_addr == func_abs)
        .collect();
    calls.sort_by_key(|n| n.entry_seq);

    println!("Calls to 0x{:x} (abs 0x{:x}):  {} calls",
             func_offset, func_abs, calls.len());
    println!();

    for (i, node) in calls.iter().enumerate() {
        let duration = if node.exit_seq != u32::MAX {
            format!("{} lines", node.exit_seq - node.entry_seq)
        } else {
            "no return".to_string()
        };

        println!("Call #{:<3}  seq={:<10}  ret={:<10}  ({})",
                 i + 1,
                 node.entry_seq,
                 if node.exit_seq != u32::MAX { format!("{}", node.exit_seq) } else { "-".to_string() },
                 duration);

        // Show the bl/blr instruction (1 line before entry) and first line of callee
        if node.entry_seq > 0 {
            if let Some(bl_line) = line_view.get_line(data, node.entry_seq - 1) {
                let line = String::from_utf8_lossy(bl_line);
                println!("  [{}] {}", node.entry_seq - 1, line);
            }
        }
        if let Some(entry_line) = line_view.get_line(data, node.entry_seq) {
            let line = String::from_utf8_lossy(entry_line);
            println!("  [{}] {}", node.entry_seq, line);
        }
        println!();
    }

    Ok(())
}

pub fn print_memdump(session: &Session, addr_str: &str, size: usize, at: Option<u32>) -> Result<()> {
    // Parse hex address
    let addr_clean = addr_str.strip_prefix("0x").unwrap_or(addr_str);
    let addr = u64::from_str_radix(addr_clean, 16)
        .map_err(|_| anyhow::anyhow!("invalid hex address: {}", addr_str))?;

    let size = if size > MAX_MEMDUMP_SIZE {
        eprintln!("warning: size {} exceeds max {}, truncating", size, MAX_MEMDUMP_SIZE);
        MAX_MEMDUMP_SIZE
    } else {
        size
    };

    if size == 0 {
        bail!("size must be > 0");
    }

    // Resolve the seq cutoff
    let at_seq = at.unwrap_or(session.total_lines.saturating_sub(1));

    let mem_view = session.mem_accesses_view();

    // Build the memory buffer by finding the last write to each byte.
    // Query all addresses in range [addr - 15, addr + size) to catch multi-byte writes
    // that overlap our target range. ARM64 max access size is 16 bytes (ldp/stp pair).
    let lo = addr.saturating_sub(15);
    let hi = addr + size as u64;

    // Collect (byte_idx, seq, value) and pick the write with highest seq per byte.
    let mut byte_state: Vec<(u32, u8)> = vec![(0, 0); size]; // (best_seq, value)
    let mut byte_has_write: Vec<bool> = vec![false; size];
    // For bytes with no WRITE: track first READ to recover initial memory state
    // (e.g. JNI-written data that the SO reads but never writes)
    let mut byte_first_read: Vec<(u32, u8)> = vec![(u32::MAX, 0); size]; // (first_read_seq, value)
    let mut byte_has_read: Vec<bool> = vec![false; size];

    for (rec_addr, records) in mem_view.query_range(lo, hi) {
        for rec in records {
            if rec.seq > at_seq {
                continue;
            }
            let access_size = rec.size as u64;
            for byte_off in 0..access_size {
                let byte_addr = rec_addr + byte_off;
                if byte_addr >= addr && byte_addr < addr + size as u64 {
                    let buf_idx = (byte_addr - addr) as usize;
                    let byte_val = ((rec.data >> (byte_off * 8)) & 0xFF) as u8;
                    if rec.is_write() {
                        if !byte_has_write[buf_idx] || rec.seq > byte_state[buf_idx].0 {
                            byte_state[buf_idx] = (rec.seq, byte_val);
                            byte_has_write[buf_idx] = true;
                        }
                    } else {
                        // READ: keep the first (lowest seq) read for initial state
                        if !byte_has_read[buf_idx] || rec.seq < byte_first_read[buf_idx].0 {
                            byte_first_read[buf_idx] = (rec.seq, byte_val);
                            byte_has_read[buf_idx] = true;
                        }
                    }
                }
            }
        }
    }

    // Build final buffer: WRITE takes priority; fall back to first READ for initial state
    let final_buf: Vec<Option<u8>> = (0..size)
        .map(|i| {
            if byte_has_write[i] {
                Some(byte_state[i].1)
            } else if byte_has_read[i] {
                Some(byte_first_read[i].1)
            } else {
                None
            }
        })
        .collect();

    // Count how many bytes came from READ fallback
    let read_fill_count = (0..size).filter(|&i| !byte_has_write[i] && byte_has_read[i]).count();

    // Print hexdump
    let known_count = final_buf.iter().filter(|b| b.is_some()).count();
    let write_count = byte_has_write.iter().filter(|&&b| b).count();
    if read_fill_count > 0 {
        println!("Memory at 0x{:x}, {} bytes (at seq {}):  ({}/{} bytes known, {} from writes, {} from reads)",
                 addr, size, at_seq, known_count, size, write_count, read_fill_count);
    } else {
        println!("Memory at 0x{:x}, {} bytes (at seq {}):  ({}/{} bytes known)",
                 addr, size, at_seq, known_count, size);
    }
    println!();

    for row_start in (0..size).step_by(16) {
        let row_end = (row_start + 16).min(size);
        // Address column
        print!("0x{:08x}: ", addr + row_start as u64);

        // Hex bytes (two groups of 8)
        for i in row_start..row_start + 16 {
            if i == row_start + 8 {
                print!(" ");
            }
            if i < row_end {
                match final_buf[i] {
                    Some(b) => print!("{:02x} ", b),
                    None => print!("?? "),
                }
            } else {
                print!("   ");
            }
        }

        // ASCII column
        print!(" |");
        for i in row_start..row_end {
            match final_buf[i] {
                Some(b) if b.is_ascii_graphic() || b == b' ' => print!("{}", b as char),
                Some(_) => print!("."),
                None => print!("?"),
            }
        }
        println!("|");
    }

    Ok(())
}
