use tauri::{AppHandle, Emitter, State};
use crate::cache;
use crate::flat::archives::{CachedStore, Phase2Archive, ScanArchive};
use crate::flat::convert;
use crate::flat::line_index::LineIndexArchive;
use crate::state::AppState;
use crate::taint;

#[tauri::command]
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
    force: Option<bool>,
    skip_strings: Option<bool>,
) -> Result<(), String> {
    let result = build_index_inner(&session_id, &app, &state, force.unwrap_or(false), skip_strings.unwrap_or(false)).await;

    // 无论成功或失败，都发送 done 事件，防止前端永远卡在 loading
    let (error, total_lines, has_string_index) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let s = sessions.get(&*session_id);
        (
            result.as_ref().err().cloned(),
            s.map(|s| s.total_lines).unwrap_or(0),
            s.and_then(|s| s.string_index.as_ref())
                .map(|si| !si.strings.is_empty())
                .unwrap_or(false),
        )
    };
    let _ = app.emit("index-progress", serde_json::json!({
        "sessionId": session_id,
        "progress": 1.0,
        "done": true,
        "error": error,
        "totalLines": total_lines,
        "hasStringIndex": has_string_index,
    }));

    // MemAccessIndex 和字符串索引现在在 Phase 2 merge 阶段一起构建，无需后台重建

    result
}

/// Internal enum to distinguish cache-hit vs fresh-scan results from the blocking closure.
enum IndexResult {
    CacheHit {
        phase2_store: CachedStore<Phase2Archive>,
        call_tree: crate::taint::call_tree::CallTree,
        string_index: Option<crate::taint::strings::StringIndex>,
        scan_store: CachedStore<ScanArchive>,
        reg_last_def: crate::taint::scanner::RegLastDef,
        lidx_store: CachedStore<LineIndexArchive>,
        total_lines: u32,
        format: crate::taint::types::TraceFormat,
        call_annotations: std::collections::HashMap<u32, crate::taint::gumtrace_parser::CallAnnotation>,
        consumed_seqs: Vec<u32>,
    },
    ScanResult(taint::ScanResult),
}

async fn build_index_inner(
    session_id: &str,
    app: &AppHandle,
    state: &State<'_, AppState>,
    force: bool,
    skip_strings: bool,
) -> Result<(), String> {
    let (mmap_arc, file_path) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        (session.mmap.clone(), session.file_path.clone())
    };

    let app_clone = app.clone();
    let session_id_clone = session_id.to_string();
    let progress_fn: taint::ProgressFn = Box::new(move |processed, total| {
        let progress = processed as f64 / total as f64;
        let _ = app_clone.emit("index-progress", serde_json::json!({
            "sessionId": session_id_clone,
            "progress": progress,
            "done": false,
        }));
    });

    let app_for_init = app.clone();
    let sid_for_init = session_id.to_string();

    let result = tauri::async_runtime::spawn_blocking(move || {
        let data: &[u8] = &mmap_arc;

        // 检测格式（在缓存逻辑之前，确保后续路径都使用正确的格式）
        let detected_format = taint::gumtrace_parser::detect_format(data);
        eprintln!("[index] detected_format={:?}, force={}, file_path={}", detected_format, force, file_path);

        // 尝试从缓存加载（三个核心缓存全部命中时使用）
        if !force {
            if let (Some(p2_mmap), Some(scan_mmap), Some(lidx_mmap)) = (
                cache::load_phase2_cache(&file_path, data),
                cache::load_scan_cache(&file_path, data),
                cache::load_lidx_cache(&file_path, data),
            ) {
                let string_index = cache::load_string_cache(&file_path, data);

                // Gumtrace 格式的 call_annotations/consumed_seqs 从独立缓存加载
                let (call_annotations, consumed_seqs) = if detected_format == crate::taint::types::TraceFormat::Gumtrace {
                    cache::load_gumtrace_extra(&file_path, data)
                        .unwrap_or_else(|| (std::collections::HashMap::new(), Vec::new()))
                } else {
                    (std::collections::HashMap::new(), Vec::new())
                };

                // Build CachedStore instances
                let phase2_store = CachedStore::Mapped(p2_mmap);
                let call_tree = phase2_store.deserialize_call_tree();

                let scan_store = CachedStore::Mapped(scan_mmap);
                let reg_last_def = scan_store.deserialize_reg_last_def();

                let lidx_store = CachedStore::Mapped(lidx_mmap);
                let total_lines = lidx_store.total_lines();

                eprintln!("[index] section cache hit: total_lines={}, format={:?}", total_lines, detected_format);
                return Ok(IndexResult::CacheHit {
                    phase2_store,
                    call_tree,
                    string_index,
                    scan_store,
                    reg_last_def,
                    lidx_store,
                    total_lines,
                    format: detected_format,
                    call_annotations,
                    consumed_seqs,
                });
            }
        }

        // 无缓存: 统一扫描 — 发送初始进度
        let _ = app_for_init.emit("index-progress", serde_json::json!({
            "sessionId": sid_for_init,
            "progress": 0.0,
            "done": false,
        }));
        // Determine number of parallel chunks based on available CPU cores
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let mut scan_result = taint::parallel::scan_unified_parallel(
            data, false, false, skip_strings, Some(progress_fn), num_cpus,
        ).map_err(|e| format!("统一扫描失败: {}", e))?;

        // 格式检查：如果没有任何行被成功解析，说明不是有效的 trace 文件
        if scan_result.scan_state.parsed_count == 0 && scan_result.scan_state.line_count > 0 {
            return Err("文件格式不正确：未检测到有效的 ARM64 trace 指令行".to_string());
        }

        // 格式检查：有指令行但没有内存操作注解（仅 unidbg 格式需要检查）
        if scan_result.scan_state.parsed_count > 0
            && scan_result.scan_state.mem_op_count == 0
            && scan_result.format == crate::taint::types::TraceFormat::Unidbg
        {
            return Err(
                "Trace 日志缺少内存访问注解（mem[WRITE]/mem[READ] 和 abs= 字段）。\n\n\
                 trace-ui 需要定制化的 unidbg 日志格式，标准 unidbg 输出不包含这些字段。\n\
                 请参考项目文档中的 unidbg 定制说明，启用内存读写打印后重新生成 trace 日志。"
                    .to_string(),
            );
        }

        // 压缩
        eprintln!("[index] scan complete, compacting...");
        scan_result.scan_state.compact();
        eprintln!("[index] compact done");

        // 缓存写入移至 session 存储之后的后台线程，不阻塞用户
        eprintln!("[index] returning scan_result from spawn_blocking");
        Ok::<_, String>(IndexResult::ScanResult(scan_result))
    })
    .await
    .map_err(|e| format!("扫描线程 panic: {}", e))??;

    eprintln!("[index] spawn_blocking returned, writing to session...");

    // 写入结果到 session
    match result {
        IndexResult::CacheHit {
            phase2_store,
            call_tree,
            string_index,
            scan_store,
            reg_last_def,
            lidx_store,
            total_lines,
            format,
            call_annotations,
            consumed_seqs,
        } => {
            let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
            if let Some(session) = sessions.get_mut(session_id) {
                session.total_lines = total_lines;
                session.trace_format = format;
                session.call_annotations = call_annotations;
                session.consumed_seqs = consumed_seqs;
                session.rebuild_call_search_texts();

                // Populate session from cache
                session.call_tree = Some(call_tree);
                session.string_index = string_index;
                session.reg_last_def = Some(reg_last_def);
                session.phase2_store = Some(phase2_store);
                session.scan_store = Some(scan_store);
                session.lidx_store = Some(lidx_store);

                eprintln!("[index] session populated from section cache");
            }
            // 缓存命中，无需再次保存
        }
        IndexResult::ScanResult(scan_result) => {
            // 1. 在 write lock 外构建 archives（不阻塞其他 session 操作）
            let phase2 = scan_result.phase2;
            let call_tree = phase2.call_tree.clone();
            let string_index = phase2.string_index;

            let phase2_archive = Phase2Archive {
                mem_accesses: convert::mem_access_to_flat(&phase2.mem_accesses),
                reg_checkpoints: convert::reg_checkpoints_to_flat(&phase2.reg_checkpoints),
                call_tree: phase2.call_tree,
            };

            let scan_state = &scan_result.scan_state;
            let scan_archive = ScanArchive {
                deps: convert::deps_to_flat(&scan_state.deps),
                mem_last_def: convert::mem_last_def_to_flat(&scan_state.mem_last_def),
                pair_split: convert::pair_split_to_flat(&scan_state.pair_split),
                init_mem_loads: convert::bitvec_to_flat(&scan_state.init_mem_loads),
                reg_last_def_inner: scan_state.reg_last_def.inner().to_vec(),
                line_count: scan_state.line_count,
                parsed_count: scan_state.parsed_count,
                mem_op_count: scan_state.mem_op_count,
            };
            let reg_last_def = scan_state.reg_last_def.clone();

            let lidx_archive = convert::line_index_to_archive(&scan_result.line_index);

            // 2. 序列化为 bytes（to_sections 只借用 &self，之后 archive 仍可 move 进 session）
            eprintln!("[index] serializing archives to cache bytes...");
            let p2_bytes = phase2_archive.to_sections();
            let scan_bytes = scan_archive.to_sections();
            let lidx_bytes = lidx_archive.to_sections();
            let si_bytes = bincode::serialize(&string_index).ok();
            eprintln!("[index] serialization done: p2={}B scan={}B lidx={}B",
                p2_bytes.len(), scan_bytes.len(), lidx_bytes.len());

            // 3. 短暂 write lock：仅存储数据到 session
            let (fp, mmap_arc, gum_extra) = {
                let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
                if let Some(session) = sessions.get_mut(session_id) {
                    session.total_lines = scan_result.line_index.total_lines();
                    session.trace_format = scan_result.format;

                    session.call_tree = Some(call_tree);
                    session.string_index = Some(string_index);
                    session.reg_last_def = Some(reg_last_def);
                    session.phase2_store = Some(CachedStore::Owned(phase2_archive));
                    session.scan_store = Some(CachedStore::Owned(scan_archive));
                    session.lidx_store = Some(CachedStore::Owned(lidx_archive));

                    session.call_annotations = scan_result.call_annotations;
                    session.consumed_seqs = scan_result.consumed_seqs;
                    session.rebuild_call_search_texts();

                    // 提取 gumtrace extra（在锁内 clone，数据量小）
                    let gum_extra = if session.trace_format == crate::taint::types::TraceFormat::Gumtrace
                        && !session.call_annotations.is_empty()
                    {
                        Some((session.call_annotations.clone(), session.consumed_seqs.clone()))
                    } else {
                        None
                    };

                    (session.file_path.clone(), session.mmap.clone(), gum_extra)
                } else {
                    return Ok(());
                }
            };
            // write lock 已释放

            // 4. 后台写文件：只用预序列化的 bytes + mmap，不依赖 session
            tauri::async_runtime::spawn(async move {
                let _ = tauri::async_runtime::spawn_blocking(move || {
                    let data: &[u8] = &mmap_arc;
                    cache::save_sections_raw(&fp, data, ".p2.cache", &p2_bytes);
                    cache::save_sections_raw(&fp, data, ".scan.cache", &scan_bytes);
                    cache::save_sections_raw(&fp, data, ".lidx.cache", &lidx_bytes);
                    if let Some(si_bytes) = &si_bytes {
                        cache::save_bincode_raw(&fp, data, ".strings", si_bytes);
                    }
                    if let Some((ref anns, ref seqs)) = gum_extra {
                        cache::save_gumtrace_extra(&fp, data, anns, seqs);
                    }
                    eprintln!("[index] background cache save complete");
                }).await;
            });

            ()
        }
    };

    Ok(())
}
