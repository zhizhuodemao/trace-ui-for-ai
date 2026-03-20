use serde::Serialize;
use tauri::State;
use crate::taint::def_use::determine_def_use;
use crate::taint::insn_class;
use crate::taint::parser;
use crate::taint::gumtrace_parser;
use crate::taint::types::{parse_reg, TraceFormat, ParsedLine};
use crate::state::AppState;

/// 单次扫描最大行数（避免 24M 行全扫描卡顿）
const MAX_SCAN_RANGE: u32 = 50000;

fn parse_line_for_format(line: &str, format: TraceFormat) -> Option<ParsedLine> {
    match format {
        TraceFormat::Unidbg => parser::parse_line(line),
        TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefUseChain {
    pub def_seq: Option<u32>,
    pub use_seqs: Vec<u32>,
    pub redefined_seq: Option<u32>,
}

#[tauri::command]
pub fn get_reg_def_use_chain(
    session_id: String,
    seq: u32,
    reg_name: String,
    state: State<'_, AppState>,
) -> Result<DefUseChain, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;

    let target_reg = parse_reg(&reg_name)
        .ok_or_else(|| format!("未知寄存器: {}", reg_name))?;

    let total = session.total_lines;
    let format = session.trace_format;
    let line_index = session.line_index_view().ok_or_else(|| "索引尚未构建完成".to_string())?;

    // === 分析 anchor 行：判断 target_reg 在当前行是 DEF 还是 USE ===
    let mut anchor_is_use = false;
    let mut anchor_is_def = false;
    if let Some(raw) = line_index.get_line(&session.mmap, seq) {
        if let Ok(line_str) = std::str::from_utf8(raw) {
            if let Some(parsed) = parse_line_for_format(line_str, format) {
                let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                let (defs, uses) = determine_def_use(cls, &parsed);
                anchor_is_def = defs.iter().any(|r| *r == target_reg);
                anchor_is_use = uses.iter().any(|r| *r == target_reg);
            }
        }
    }

    // === 向上扫描：仅当 anchor 行 USE 了该寄存器时才查找上游 DEF ===
    let mut def_seq: Option<u32> = None;
    if anchor_is_use && seq > 0 {
        let scan_start = seq.saturating_sub(MAX_SCAN_RANGE);
        for s in (scan_start..seq).rev() {
            if let Some(raw) = line_index.get_line(&session.mmap, s) {
                if let Ok(line_str) = std::str::from_utf8(raw) {
                    if let Some(parsed) = parse_line_for_format(line_str, format) {
                        let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                        let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                        let (defs, _) = determine_def_use(cls, &parsed);
                        if defs.iter().any(|r| *r == target_reg) {
                            def_seq = Some(s);
                            break;
                        }
                    }
                }
            }
        }
    }

    // === 向下扫描：仅当 anchor 行 DEF 了该寄存器时才收集下游 USE ===
    let mut use_seqs: Vec<u32> = Vec::new();
    let mut redefined_seq: Option<u32> = None;
    if anchor_is_def {
        let scan_end = total.min(seq + MAX_SCAN_RANGE);
        for s in (seq + 1)..scan_end {
            if let Some(raw) = line_index.get_line(&session.mmap, s) {
                if let Ok(line_str) = std::str::from_utf8(raw) {
                    if let Some(parsed) = parse_line_for_format(line_str, format) {
                        let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                        let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                        let (defs, uses) = determine_def_use(cls, &parsed);

                        // 先检查 USE（同一行可能既 USE 又 DEF，如 add x0, x0, #1）
                        if uses.iter().any(|r| *r == target_reg) {
                            use_seqs.push(s);
                        }

                        // 再检查 DEF（重新定义 = 扫描终点）
                        if defs.iter().any(|r| *r == target_reg) {
                            redefined_seq = Some(s);
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(DefUseChain {
        def_seq,
        use_seqs,
        redefined_seq,
    })
}
