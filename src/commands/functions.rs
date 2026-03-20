use serde::Serialize;
use std::collections::HashMap;
use tauri::State;
use crate::state::AppState;

#[derive(Serialize)]
pub struct FunctionCallOccurrence {
    pub seq: u32,
    pub summary: String,
}

#[derive(Serialize)]
pub struct FunctionCallEntry {
    pub func_name: String,
    pub is_jni: bool,
    pub occurrences: Vec<FunctionCallOccurrence>,
}

#[derive(Serialize)]
pub struct FunctionCallsResult {
    pub functions: Vec<FunctionCallEntry>,
    pub total_calls: usize,
}

#[tauri::command]
pub fn get_function_calls(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<FunctionCallsResult, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} not found", session_id))?;

    // Group by func_name
    let mut groups: HashMap<String, (bool, Vec<FunctionCallOccurrence>)> = HashMap::new();
    for (&seq, ann) in &session.call_annotations {
        let entry = groups.entry(ann.func_name.clone()).or_insert_with(|| (ann.is_jni, Vec::new()));
        entry.1.push(FunctionCallOccurrence {
            seq,
            summary: ann.summary(),
        });
    }

    let mut total_calls = 0usize;
    let mut functions: Vec<FunctionCallEntry> = groups.into_iter()
        .map(|(func_name, (is_jni, mut occs))| {
            occs.sort_by_key(|o| o.seq);
            total_calls += occs.len();
            FunctionCallEntry { func_name, is_jni, occurrences: occs }
        })
        .collect();

    // Sort by first occurrence seq
    functions.sort_by_key(|f| f.occurrences.first().map(|o| o.seq).unwrap_or(u32::MAX));

    Ok(FunctionCallsResult { functions, total_calls })
}
