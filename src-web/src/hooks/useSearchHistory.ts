import { useState, useCallback, useEffect, useRef } from "react";

const DEFAULT_MAX = 20;

interface UseSearchHistoryOptions {
  storageKey: string;
  maxItems?: number;
}

export function useSearchHistory({ storageKey, maxItems = DEFAULT_MAX }: UseSearchHistoryOptions) {
  const [history, setHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(storageKey) || "[]"); } catch { return []; }
  });
  const [showHistory, setShowHistory] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  // Click outside to close history dropdown
  useEffect(() => {
    if (!showHistory) return;
    const handler = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setShowHistory(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showHistory]);

  const addToHistory = useCallback((q: string) => {
    const trimmed = q.trim();
    if (!trimmed) return;
    setHistory(prev => {
      const next = [trimmed, ...prev.filter(h => h !== trimmed)].slice(0, maxItems);
      localStorage.setItem(storageKey, JSON.stringify(next));
      return next;
    });
  }, [storageKey, maxItems]);

  const removeHistoryItem = useCallback((item: string) => {
    setHistory(prev => {
      const next = prev.filter(h => h !== item);
      localStorage.setItem(storageKey, JSON.stringify(next));
      return next;
    });
  }, [storageKey]);

  const clearAllHistory = useCallback(() => {
    setHistory([]);
    localStorage.removeItem(storageKey);
    setShowHistory(false);
  }, [storageKey]);

  const getFilteredHistory = useCallback((currentInput: string) => {
    const trimmed = currentInput.trim();
    if (!trimmed) return history;
    const lower = trimmed.toLowerCase();
    return history.filter(h => h !== trimmed && h.toLowerCase().includes(lower));
  }, [history]);

  return {
    history,
    showHistory,
    setShowHistory,
    wrapperRef,
    addToHistory,
    removeHistoryItem,
    clearAllHistory,
    getFilteredHistory,
  };
}
