use serde::Serialize;
use tauri::State;
use crate::state::AppState;
use crate::taint::strings::StringEncoding;
use crate::phase2::extract_insn_offset;

#[derive(Serialize)]
pub struct StringRecordDto {
    pub idx: u32,
    pub addr: String,
    pub content: String,
    pub encoding: String,
    pub byte_len: u32,
    pub seq: u32,
    pub xref_count: u32,
}

#[derive(Serialize)]
pub struct StringsResult {
    pub strings: Vec<StringRecordDto>,
    pub total: u32,
}

#[derive(Serialize)]
pub struct StringXRef {
    pub seq: u32,
    pub rw: String,
    pub insn_addr: String,
    pub disasm: String,
}

#[tauri::command]
pub fn get_strings(
    session_id: String,
    min_len: u32,
    offset: u32,
    limit: u32,
    search: Option<String>,
    state: State<'_, AppState>,
) -> Result<StringsResult, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let string_index = session.string_index.as_ref().ok_or("索引尚未构建完成")?;

    let search_lower = search.as_ref().map(|s| s.to_lowercase());

    let filtered: Vec<(usize, &crate::taint::strings::StringRecord)> = string_index.strings
        .iter()
        .enumerate()
        .filter(|(_, r)| r.byte_len >= min_len)
        .filter(|(_, r)| {
            match &search_lower {
                Some(q) => r.content.to_lowercase().contains(q.as_str()),
                None => true,
            }
        })
        .collect();

    let total = filtered.len() as u32;
    let page: Vec<StringRecordDto> = filtered
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(idx, r)| StringRecordDto {
            idx: idx as u32,
            addr: format!("0x{:x}", r.addr),
            content: r.content.clone(),
            encoding: match r.encoding {
                StringEncoding::Ascii => "ASCII".to_string(),
                StringEncoding::Utf8 => "UTF-8".to_string(),
            },
            byte_len: r.byte_len,
            seq: r.seq,
            xref_count: r.xref_count,
        })
        .collect();

    Ok(StringsResult { strings: page, total })
}

#[tauri::command]
pub fn get_string_xrefs(
    session_id: String,
    addr: String,
    byte_len: u32,
    state: State<'_, AppState>,
) -> Result<Vec<StringXRef>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let mem_view = session.mem_accesses_view().ok_or("索引尚未构建完成")?;



    let addr_str = addr.trim_start_matches("0x").trim_start_matches("0X");
    let base_addr = u64::from_str_radix(addr_str, 16)
        .map_err(|_| format!("无效地址: {}", addr))?;

    let line_index = session.line_index_view().ok_or("行索引未就绪")?;
    let mmap = &session.mmap;

    let mut xrefs: Vec<StringXRef> = Vec::new();
    let mut seen_seqs = std::collections::HashSet::new();

    for offset in 0..byte_len as u64 {
        let target = base_addr + offset;
        if let Some(records) = mem_view.query(target) {
            for rec in records {
                if seen_seqs.insert(rec.seq) {
                    let rw_str = if rec.is_read() { "R" } else { "W" };
                    let disasm = line_index.get_line(mmap, rec.seq)
                        .and_then(|raw| {
                            match session.trace_format {
                                crate::taint::types::TraceFormat::Unidbg => crate::commands::browse::parse_trace_line(rec.seq, raw),
                                crate::taint::types::TraceFormat::Gumtrace => crate::commands::browse::parse_trace_line_gumtrace(rec.seq, raw),
                            }
                            .map(|t| t.disasm)
                        })
                        .unwrap_or_default();
                    let insn_addr_str = line_index.get_line(mmap, rec.seq)
                        .and_then(|raw| std::str::from_utf8(raw).ok())
                        .map(|line_str| {
                            let offset = extract_insn_offset(line_str);
                            if offset != 0 { format!("0x{:x}", offset) } else { format!("0x{:x}", rec.insn_addr) }
                        })
                        .unwrap_or_else(|| format!("0x{:x}", rec.insn_addr));
                    xrefs.push(StringXRef {
                        seq: rec.seq,
                        rw: rw_str.to_string(),
                        insn_addr: insn_addr_str,
                        disasm,
                    });
                }
            }
        }
    }

    xrefs.sort_by_key(|x| x.seq);
    Ok(xrefs)
}

#[tauri::command]
pub async fn scan_strings(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 1. Collect Write records and get cancellation flag
    let (mut writes, cancelled) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        let mem_view = session.mem_accesses_view().ok_or("索引尚未构建完成")?;

        let mut writes: Vec<(u64, u64, u8, u32)> = Vec::new();
        for (addr, rec) in mem_view.iter_all() {
            if rec.is_write() && rec.size <= 8 {
                writes.push((addr, rec.data, rec.size, rec.seq));
            }
        }
        (writes, session.scan_strings_cancelled.clone())
    };

    // 2. Sort by seq
    writes.sort_unstable_by_key(|w| w.3);

    // 3. Reset cancellation flag
    cancelled.store(false, std::sync::atomic::Ordering::SeqCst);

    // 4. Run StringBuilder in blocking thread
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut sb = crate::taint::strings::StringBuilder::new();
        for (i, &(addr, data, size, seq)) in writes.iter().enumerate() {
            if i % 10000 == 0 && cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("cancelled".to_string());
            }
            sb.process_write(addr, data, size, seq);
        }
        Ok(sb)
    })
    .await
    .map_err(|e| format!("扫描线程 panic: {}", e))??;

    // 5. finish + fill_xref_counts
    let mut string_index = result.finish();
    {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        let mem_view = session.mem_accesses_view().ok_or("索引尚未构建完成")?;
        crate::taint::strings::StringBuilder::fill_xref_counts_view(&mut string_index, &mem_view);
    }

    // 6. Write results and update cache
    {
        let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
        let session = sessions.get_mut(&session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        crate::cache::save_string_cache(&session.file_path, &*session.mmap, &string_index);
        session.string_index = Some(string_index);
    }

    Ok(())
}

#[tauri::command]
pub async fn cancel_scan_strings(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    if let Some(session) = sessions.get(&session_id) {
        session.scan_strings_cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
