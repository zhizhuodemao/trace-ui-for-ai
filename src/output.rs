use anyhow::{bail, Result};
use rustc_hash::FxHashMap;

use crate::core::slicer::bfs_slice_with_options;
use crate::core::types::parse_reg;
use crate::func_stats::compute_func_stats;
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

pub fn print_overview(session: &Session) {
    let data: &[u8] = &session.mmap;
    let module_name = extract_module_name(data);
    println!("Trace: {}  {} lines  unidbg", module_name, session.total_lines);
    println!();

    let stats = compute_func_stats(&session.call_tree);
    let max_depth: u32 = 2;
    let mut printed = 0usize;
    let total_eligible = stats.iter().filter(|s| s.depth <= max_depth).count();

    for s in &stats {
        if s.depth > max_depth {
            continue;
        }
        if printed >= MAX_LINES {
            let remaining = total_eligible - printed;
            if remaining > 0 {
                println!("... {} more functions", remaining);
            }
            break;
        }

        let indent = "  ".repeat(s.depth as usize);
        let loop_info = s.children.iter()
            .filter(|(_, count)| *count > 1)
            .map(|(_, count)| format!("loop:{}", count))
            .collect::<Vec<_>>();
        let loop_str = if loop_info.is_empty() {
            String::new()
        } else {
            format!("  [{}]", loop_info.join(", "))
        };

        let addr_str = if s.func_addr != 0 {
            format!("0x{:x}", s.func_addr)
        } else {
            "root".to_string()
        };

        println!(
            "{}{}  {} insns  x{}{}",
            indent, addr_str, s.insn_count,
            s.children.len(),
            loop_str
        );
        printed += 1;
    }
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

pub fn print_taint(session: &Session, spec: &str, after: Option<u32>, data_only: bool, ignore_sp: bool) -> Result<()> {
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

    // Count tainted in range if --after is specified
    let (tainted_in_range, header_suffix) = if let Some(after_seq) = after {
        let count = marked.iter().enumerate()
            .filter(|(i, is_set)| **is_set && (*i as u32) >= after_seq)
            .count();
        (count, format!("  (showing seq >= {})  ({} tainted in range / {} total tainted / {} lines)",
                        after_seq, count, total_marked, session.total_lines))
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
        // Apply --after filter
        if let Some(after_seq) = after {
            if (i as u32) < after_seq {
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

pub fn print_search(session: &Session, pattern: &str) {
    let data: &[u8] = &session.mmap;
    let view = session.line_index_view();
    let pattern_lower = pattern.to_ascii_lowercase();

    let mut matches: Vec<(u32, String)> = Vec::new();
    let mut total_matches: usize = 0;

    for seq in 0..session.total_lines {
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

    println!("Search: \"{}\"  {} matches", pattern, total_matches);
    println!();

    for (seq, line) in &matches {
        println!("[{}] {}", seq, line);
    }

    if total_matches > MAX_SEARCH_RESULTS {
        println!("... {} more matches", total_matches - MAX_SEARCH_RESULTS);
    }
}

pub fn print_calltree(session: &Session, addr_str: &str) -> Result<()> {
    // Parse hex address: accept "0x1209e184" or "1209e184"
    let addr_clean = addr_str.strip_prefix("0x").unwrap_or(addr_str);
    let addr = u64::from_str_radix(addr_clean, 16)
        .map_err(|_| anyhow::anyhow!("invalid hex address: {}", addr_str))?;

    let tree = &session.call_tree;

    // Find the node matching this address (pick the first/root-level one)
    let node = tree.nodes.iter().find(|n| n.func_addr == addr);

    let node = match node {
        Some(n) => n,
        None => {
            bail!("address 0x{:x} not found in call tree", addr);
        }
    };

    // Auto-flatten: follow single-child chains to reach the "real" node
    let mut current = node;
    let mut wrappers_skipped: u32 = 0;
    while current.children_ids.len() == 1 {
        let child = &tree.nodes[current.children_ids[0] as usize];
        current = child;
        wrappers_skipped += 1;
    }

    let insn_count = current.exit_seq.saturating_sub(current.entry_seq);
    if wrappers_skipped > 0 {
        println!("0x{:x} -> 0x{:x} (via {} wrappers)  seq {}-{}  {} insns",
                 node.func_addr, current.func_addr, wrappers_skipped,
                 current.entry_seq, current.exit_seq, insn_count);
    } else {
        println!("0x{:x}  seq {}-{}  {} insns",
                 current.func_addr, current.entry_seq, current.exit_seq, insn_count);
    }

    if current.children_ids.is_empty() {
        println!("  (no children)");
        return Ok(());
    }

    // Group children by func_addr, collect stats
    // Also track if each child group is itself a single-child chain (flatten in listing)
    let mut child_groups: FxHashMap<u64, (u32, u32, u32, u32)> = FxHashMap::default();
    // value: (count, min_entry_seq, max_exit_seq, total_insns)
    // For single-child flattening in children, collect flattened info per child_id
    struct FlattenedChild {
        display_addr: u64,
        wrappers: u32,
    }
    let mut flattened_children: Vec<FlattenedChild> = Vec::new();

    for &child_id in &current.children_ids {
        let child = &tree.nodes[child_id as usize];
        // Follow single-child chains for this child too
        let mut inner = child;
        let mut child_wrappers: u32 = 0;
        while inner.children_ids.len() == 1 {
            inner = &tree.nodes[inner.children_ids[0] as usize];
            child_wrappers += 1;
        }
        let child_insns = inner.exit_seq.saturating_sub(inner.entry_seq);
        flattened_children.push(FlattenedChild {
            display_addr: inner.func_addr,
            wrappers: child_wrappers,
        });

        // Group by the flattened display address
        let entry = child_groups.entry(inner.func_addr).or_insert((0, u32::MAX, 0, 0));
        entry.0 += 1;
        entry.1 = entry.1.min(inner.entry_seq);
        entry.2 = entry.2.max(inner.exit_seq);
        entry.3 += child_insns;
    }

    // Build groups for display, including wrapper info
    struct GroupDisplay {
        addr: u64,
        count: u32,
        min_entry: u32,
        max_exit: u32,
        total_insns: u32,
        max_wrappers: u32,
    }
    let mut group_wrappers: FxHashMap<u64, u32> = FxHashMap::default();
    for fc in &flattened_children {
        let e = group_wrappers.entry(fc.display_addr).or_insert(0);
        *e = (*e).max(fc.wrappers);
    }

    let mut groups: Vec<GroupDisplay> = child_groups
        .into_iter()
        .map(|(addr, (count, min_entry, max_exit, total_insns))| GroupDisplay {
            addr,
            count,
            min_entry,
            max_exit,
            total_insns,
            max_wrappers: group_wrappers.get(&addr).copied().unwrap_or(0),
        })
        .collect();
    // Sort by first appearance (min_entry_seq)
    groups.sort_unstable_by_key(|g| g.min_entry);

    println!("  children:");

    let max_children = 50;
    let total_groups = groups.len();
    for (i, g) in groups.iter().enumerate() {
        if i >= max_children {
            println!("    ... {} more children", total_groups - max_children);
            break;
        }
        let via = if g.max_wrappers > 0 {
            format!("  (via {} wrappers)", g.max_wrappers)
        } else {
            String::new()
        };
        println!("    0x{:x}  seq {}-{}  {} insns  x{}{}",
                 g.addr, g.min_entry, g.max_exit, g.total_insns, g.count, via);
    }

    Ok(())
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
