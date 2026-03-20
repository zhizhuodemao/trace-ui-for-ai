import { useState, useCallback, useRef } from "react";

export interface HighlightInfo {
  color?: string;
  strikethrough?: boolean;
  hidden?: boolean;
  comment?: string;
}

const STORAGE_PREFIX = "trace-ui-highlights-";

function hashPath(path: string): string {
  let h = 0;
  for (let i = 0; i < path.length; i++) {
    h = ((h << 5) - h + path.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}

function storageKey(filePath: string): string {
  return STORAGE_PREFIX + hashPath(filePath);
}

function load(filePath: string): Map<number, HighlightInfo> {
  try {
    const raw = localStorage.getItem(storageKey(filePath));
    if (!raw) return new Map();
    const entries: [number, HighlightInfo][] = JSON.parse(raw);
    return new Map(entries);
  } catch {
    return new Map();
  }
}

function save(filePath: string, highlights: Map<number, HighlightInfo>) {
  const entries = Array.from(highlights.entries()).filter(
    ([, v]) => v.color || v.strikethrough || v.hidden || v.comment
  );
  if (entries.length === 0) {
    localStorage.removeItem(storageKey(filePath));
  } else {
    localStorage.setItem(storageKey(filePath), JSON.stringify(entries));
  }
}

function isEmptyHighlight(info: HighlightInfo): boolean {
  return !info.color && !info.strikethrough && !info.hidden && !info.comment;
}

export function useHighlights() {
  const [highlights, setHighlights] = useState<Map<number, HighlightInfo>>(new Map());
  const filePathRef = useRef<string | null>(null);

  const loadForFile = useCallback((filePath: string | null) => {
    filePathRef.current = filePath;
    if (!filePath) {
      setHighlights(new Map());
      return;
    }
    setHighlights(load(filePath));
  }, []);

  // 通用更新函数：对每个 seq 应用 updater，自动处理空条目清理和持久化
  const updateEntries = useCallback((
    seqs: number[],
    updater: (existing: HighlightInfo, seq: number, currentMap: Map<number, HighlightInfo>) => HighlightInfo | null
  ) => {
    setHighlights(prev => {
      const next = new Map(prev);
      for (const seq of seqs) {
        const existing = next.get(seq) || {};
        const result = updater(existing, seq, prev);
        if (result === null) {
          next.delete(seq);
        } else if (isEmptyHighlight(result)) {
          next.delete(seq);
        } else {
          next.set(seq, result);
        }
      }
      if (filePathRef.current) save(filePathRef.current, next);
      return next;
    });
  }, []);

  const setHighlight = useCallback((seqs: number[], update: HighlightInfo | null) => {
    updateEntries(seqs, (existing) =>
      update === null ? null : { ...existing, ...update }
    );
  }, [updateEntries]);

  const toggleStrikethrough = useCallback((seqs: number[]) => {
    setHighlights(prev => {
      // 需要先读取 prev 判断 allHave，所以用 setHighlights 直接操作
      const allHave = seqs.every(s => prev.get(s)?.strikethrough);
      const next = new Map(prev);
      for (const seq of seqs) {
        const existing = next.get(seq) || {};
        const merged = { ...existing, strikethrough: !allHave };
        if (isEmptyHighlight(merged)) {
          next.delete(seq);
        } else {
          next.set(seq, merged);
        }
      }
      if (filePathRef.current) save(filePathRef.current, next);
      return next;
    });
  }, []);

  const resetHighlight = useCallback((seqs: number[]) => {
    updateEntries(seqs, () => null);
  }, [updateEntries]);

  const toggleHidden = useCallback((seqs: number[]) => {
    setHighlights(prev => {
      const allHidden = seqs.every(s => prev.get(s)?.hidden);
      const next = new Map(prev);
      for (const seq of seqs) {
        const existing = next.get(seq) || {};
        const merged = { ...existing, hidden: !allHidden };
        if (isEmptyHighlight(merged)) {
          next.delete(seq);
        } else {
          next.set(seq, merged);
        }
      }
      if (filePathRef.current) save(filePathRef.current, next);
      return next;
    });
  }, []);

  const unhideGroup = useCallback((seqs: number[]) => {
    updateEntries(seqs, (existing) => ({ ...existing, hidden: false }));
  }, [updateEntries]);

  const setComment = useCallback((seq: number, comment: string) => {
    const trimmed = comment.trim();
    updateEntries([seq], (existing) => ({ ...existing, comment: trimmed || undefined }));
  }, [updateEntries]);

  const deleteComment = useCallback((seq: number) => {
    updateEntries([seq], (existing, _seq, currentMap) => {
      if (!currentMap.get(seq)) return null; // 不存在则跳过（保持 prev 引用）
      return { ...existing, comment: undefined };
    });
  }, [updateEntries]);

  return { highlights, loadForFile, setHighlight, toggleStrikethrough, resetHighlight, toggleHidden, unhideGroup, setComment, deleteComment };
}
