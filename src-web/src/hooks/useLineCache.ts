import { useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { TraceLine } from "../types/trace";

const PER_SESSION_LIMIT = 5000;
const MAX_SESSIONS = 10;

export function useLineCache(sessionId: string | null) {
  const cacheMap = useRef<Map<string, Map<number, TraceLine>>>(new Map());

  const getLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    if (!sessionId) return [];

    if (!cacheMap.current.has(sessionId)) {
      cacheMap.current.set(sessionId, new Map());
      // 超过 session 数量限制时淘汰最早的
      if (cacheMap.current.size > MAX_SESSIONS) {
        const firstKey = cacheMap.current.keys().next().value;
        if (firstKey !== undefined) cacheMap.current.delete(firstKey);
      }
    }
    const cache = cacheMap.current.get(sessionId)!;

    const uncached = seqs.filter(s => !cache.has(s));
    if (uncached.length > 0) {
      const lines = await invoke<TraceLine[]>("get_lines", { sessionId, seqs: uncached });
      for (const line of lines) {
        cache.set(line.seq, line);
      }
      // FIFO 淘汰
      if (cache.size > PER_SESSION_LIMIT) {
        const keys = Array.from(cache.keys());
        for (let i = 0; i < keys.length - PER_SESSION_LIMIT; i++) {
          cache.delete(keys[i]);
        }
      }
    }
    return seqs.map(s => cache.get(s)!).filter(Boolean);
  }, [sessionId]);

  const removeSessionCache = useCallback((sid: string) => {
    cacheMap.current.delete(sid);
  }, []);

  return { getLines, removeSessionCache };
}
