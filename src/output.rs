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

pub fn print_taint(session: &Session, spec: &str, range: Option<&str>, data_only: bool, ignore_sp: bool) -> Result<()> {
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

pub fn print_search(session: &Session, pattern: &str, range: Option<&str>) {
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

    let data: &[u8] = &session.mmap;
    let view = session.line_index_view();
    let pattern_lower = pattern.to_ascii_lowercase();

    let mut matches: Vec<(u32, String)> = Vec::new();
    let mut total_matches: usize = 0;

    for seq in range_start..=range_end {
        if let Some(line_bytes) = view.get_line(data, seq) {
            let line = String::from_utf8_lossy(line_bytes);
            if line.to_ascii_lowercase().contains(&pattern_lower) {
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

    println!("Search: \"{}\"  {} matches{}", pattern, total_matches, range_suffix);
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
    let mut byte_has_data: Vec<bool> = vec![false; size];

    for (rec_addr, records) in mem_view.query_range(lo, hi) {
        for rec in records {
            if !rec.is_write() {
                continue;
            }
            if rec.seq > at_seq {
                continue;
            }
            let write_size = rec.size as u64;
            for byte_off in 0..write_size {
                let byte_addr = rec_addr + byte_off;
                if byte_addr >= addr && byte_addr < addr + size as u64 {
                    let buf_idx = (byte_addr - addr) as usize;
                    let byte_val = ((rec.data >> (byte_off * 8)) & 0xFF) as u8;
                    if !byte_has_data[buf_idx] || rec.seq > byte_state[buf_idx].0 {
                        byte_state[buf_idx] = (rec.seq, byte_val);
                        byte_has_data[buf_idx] = true;
                    }
                }
            }
        }
    }

    // Build final buffer
    let final_buf: Vec<Option<u8>> = (0..size)
        .map(|i| if byte_has_data[i] { Some(byte_state[i].1) } else { None })
        .collect();

    // Print hexdump
    let known_count = final_buf.iter().filter(|b| b.is_some()).count();
    println!("Memory at 0x{:x}, {} bytes (at seq {}):  ({}/{} bytes known)",
             addr, size, at_seq, known_count, size);
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
