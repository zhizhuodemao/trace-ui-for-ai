import { useState, useCallback, useEffect, useRef } from "react";

const STORAGE_PREFIX = "func-rename:";

function loadFromStorage(filePath: string): Map<string, string> {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + filePath);
    if (!raw) return new Map();
    const obj = JSON.parse(raw) as Record<string, string>;
    return new Map(Object.entries(obj));
  } catch {
    return new Map();
  }
}

function saveToStorage(filePath: string, map: Map<string, string>) {
  if (map.size === 0) {
    localStorage.removeItem(STORAGE_PREFIX + filePath);
  } else {
    localStorage.setItem(STORAGE_PREFIX + filePath, JSON.stringify(Object.fromEntries(map)));
  }
}

export function useFuncRenameStore(filePath: string | null) {
  const [renameMap, setRenameMap] = useState<Map<string, string>>(new Map());
  const filePathRef = useRef(filePath);

  useEffect(() => {
    filePathRef.current = filePath;
    if (filePath) {
      setRenameMap(loadFromStorage(filePath));
    } else {
      setRenameMap(new Map());
    }
  }, [filePath]);

  const setName = useCallback((addr: string, name: string) => {
    setRenameMap(prev => {
      const next = new Map(prev);
      next.set(addr, name);
      if (filePathRef.current) saveToStorage(filePathRef.current, next);
      return next;
    });
  }, []);

  const removeName = useCallback((addr: string) => {
    setRenameMap(prev => {
      const next = new Map(prev);
      next.delete(addr);
      if (filePathRef.current) saveToStorage(filePathRef.current, next);
      return next;
    });
  }, []);

  const getName = useCallback((addr: string): string | undefined => {
    return renameMap.get(addr);
  }, [renameMap]);

  return { renameMap, getName, setName, removeName };
}
