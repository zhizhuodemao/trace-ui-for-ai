use serde::Serialize;
use crate::cache;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheInfo {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    pub files_deleted: u32,
    pub bytes_freed: u64,
}

#[tauri::command]
pub fn get_cache_dir() -> CacheInfo {
    let (path, size) = cache::get_cache_info();
    CacheInfo { path, size }
}

#[tauri::command]
pub fn set_cache_dir(path: Option<String>) -> Result<(), String> {
    let path_buf = path.map(|p| std::path::PathBuf::from(p));
    if let Some(ref p) = path_buf {
        std::fs::create_dir_all(p).map_err(|e| format!("无法创建缓存目录: {}", e))?;
    }
    cache::set_cache_dir_override(path_buf);
    Ok(())
}

#[tauri::command]
pub fn clear_all_cache() -> ClearResult {
    let (files_deleted, bytes_freed) = cache::clear_all_cache();
    ClearResult { files_deleted, bytes_freed }
}
