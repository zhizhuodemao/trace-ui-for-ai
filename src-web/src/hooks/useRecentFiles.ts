import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

const STORAGE_KEY = "trace-ui-recent-files";
const MAX_ITEMS = 10;

function loadRecent(): string[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveRecent(files: string[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(files));
}

export function useRecentFiles() {
  const [recentFiles, setRecentFiles] = useState<string[]>(loadRecent);

  const addRecent = useCallback((path: string) => {
    setRecentFiles((prev) => {
      const filtered = prev.filter((p) => p !== path);
      const next = [path, ...filtered].slice(0, MAX_ITEMS);
      saveRecent(next);
      return next;
    });
  }, []);

  const removeRecent = useCallback((path: string) => {
    setRecentFiles((prev) => {
      const next = prev.filter((p) => p !== path);
      saveRecent(next);
      return next;
    });
    // 同时删除该文件的索引缓存
    invoke("delete_file_cache", { path }).catch((e) => {
      console.error("Failed to delete cache:", e);
    });
  }, []);

  const clearRecent = useCallback(() => {
    setRecentFiles([]);
    saveRecent([]);
  }, []);

  return { recentFiles, addRecent, removeRecent, clearRecent };
}
