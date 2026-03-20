fn main() {
    // 监控前端 dist 目录变化，确保 cargo build 时重新嵌入最新前端
    println!("cargo:rerun-if-changed=src-web/dist");
    tauri_build::build()
}
