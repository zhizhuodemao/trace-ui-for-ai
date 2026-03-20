import { useState, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { SliceResult } from "../types/trace";

const PAGE_SIZE = 256;

interface SessionSliceState {
  sliceActive: boolean;
  sliceInfo: SliceResult | null;
  sliceFromSpecs: string[];
  sliceFilterMode: "highlight" | "filter-only";
  taintedSeqs: number[];
  sliceStartSeq?: number;
  sliceEndSeq?: number;
  sliceSourceSeq?: number;
  sliceDataOnly?: boolean;
  sliceDuration: number | null;
  sliceError: string | null;
}

function defaultState(): SessionSliceState {
  return {
    sliceActive: false,
    sliceInfo: null,
    sliceFromSpecs: [],
    sliceFilterMode: "filter-only",
    taintedSeqs: [],
    sliceStartSeq: undefined,
    sliceEndSeq: undefined,
    sliceSourceSeq: undefined,
    sliceDuration: null,
    sliceError: null,
  };
}

export function useSliceState(sessionId: string | null) {
  // Per-session state storage
  const stateMapRef = useRef<Map<string, SessionSliceState>>(new Map());
  const sliceCacheMapRef = useRef<Map<string, Map<number, boolean[]>>>(new Map());

  const getSessionState = useCallback((sid: string | null): SessionSliceState => {
    if (!sid) return defaultState();
    if (!stateMapRef.current.has(sid)) {
      stateMapRef.current.set(sid, defaultState());
    }
    return stateMapRef.current.get(sid)!;
  }, []);

  const getSliceCache = useCallback((sid: string): Map<number, boolean[]> => {
    if (!sliceCacheMapRef.current.has(sid)) {
      sliceCacheMapRef.current.set(sid, new Map());
    }
    return sliceCacheMapRef.current.get(sid)!;
  }, []);

  // Current session's state exposed via useState for reactivity
  const [currentState, setCurrentState] = useState<SessionSliceState>(defaultState);
  const [isSlicing, setIsSlicing] = useState(false);

  // 渲染期间同步状态（非 useEffect）：React 检测到 setState 调用后会丢弃当前渲染，
  // 立即用新状态重新渲染，避免中间帧出现 sessionId=B + sliceState=A 的错误组合
  const prevSessionIdRef = useRef<string | null>(null);
  if (sessionId !== prevSessionIdRef.current) {
    prevSessionIdRef.current = sessionId;
    setCurrentState(getSessionState(sessionId));
  }

  const updateState = useCallback((sid: string, updates: Partial<SessionSliceState>) => {
    const existing = stateMapRef.current.get(sid) ?? defaultState();
    const updated = { ...existing, ...updates };
    stateMapRef.current.set(sid, updated);
    // Only trigger re-render if this is the active session
    if (sid === prevSessionIdRef.current) {
      setCurrentState(updated);
    }
  }, []);

  const runSlice = useCallback(async (fromSpecs: string[], startSeq?: number, endSeq?: number, sourceSeq?: number, dataOnly?: boolean): Promise<SliceResult | undefined> => {
    if (!sessionId || fromSpecs.length === 0) return undefined;
    setIsSlicing(true);
    const startTime = performance.now();
    try {
      const result = await invoke<SliceResult>("run_slice", {
        sessionId,
        fromSpecs,
        startSeq: startSeq ?? null,
        endSeq: endSeq ?? null,
        dataOnly: dataOnly ?? false,
      });
      getSliceCache(sessionId).clear();
      const seqs = await invoke<number[]>("get_tainted_seqs", { sessionId });
      updateState(sessionId, {
        sliceActive: true,
        sliceInfo: result,
        sliceFromSpecs: fromSpecs,
        sliceFilterMode: "filter-only",
        taintedSeqs: seqs,
        sliceStartSeq: startSeq,
        sliceEndSeq: endSeq,
        sliceSourceSeq: sourceSeq,
        sliceDataOnly: dataOnly,
        sliceDuration: performance.now() - startTime,
        sliceError: null,
      });
      return result;
    } catch (e) {
      console.error("run_slice failed:", e);
      updateState(sessionId, { sliceError: String(e), sliceDuration: null });
      throw e;
    } finally {
      setIsSlicing(false);
    }
  }, [sessionId, updateState, getSliceCache]);

  const clearSlice = useCallback(() => {
    if (!sessionId) return;
    // 先同步更新 UI 状态（即时退出污点模式），再 fire-and-forget 发送 IPC。
    // 避免 await 期间后端写锁被前端预取的读锁饿死导致 UI 卡顿数秒。
    getSliceCache(sessionId).clear();
    updateState(sessionId, defaultState());
    invoke("clear_slice", { sessionId }).catch(console.error);
  }, [sessionId, updateState, getSliceCache]);

  const setSliceFilterMode = useCallback((mode: "highlight" | "filter-only") => {
    if (!sessionId) return;
    updateState(sessionId, { sliceFilterMode: mode });
  }, [sessionId, updateState]);

  const getSliceStatus = useCallback(async (startSeq: number, count: number): Promise<boolean[]> => {
    if (!sessionId || !currentState.sliceActive) return new Array(count).fill(false);

    const cache = getSliceCache(sessionId);
    const startPage = Math.floor(startSeq / PAGE_SIZE);
    const endPage = Math.floor((startSeq + count - 1) / PAGE_SIZE);

    for (let page = startPage; page <= endPage; page++) {
      if (!cache.has(page)) {
        const pageStart = page * PAGE_SIZE;
        const statuses = await invoke<boolean[]>("get_slice_status", {
          sessionId,
          startSeq: pageStart,
          count: PAGE_SIZE,
        });
        cache.set(page, statuses);
      }
    }

    const result: boolean[] = [];
    for (let i = 0; i < count; i++) {
      const seq = startSeq + i;
      const page = Math.floor(seq / PAGE_SIZE);
      const offset = seq % PAGE_SIZE;
      const cached = cache.get(page);
      result.push(cached ? cached[offset] ?? false : false);
    }

    return result;
  }, [sessionId, currentState.sliceActive, getSliceCache]);

  // Clean up when a session is removed
  const removeSession = useCallback((sid: string) => {
    stateMapRef.current.delete(sid);
    sliceCacheMapRef.current.delete(sid);
  }, []);

  // 获取指定 session 的 slice 状态（用于持久化保存）
  const getStateForSession = useCallback((sid: string) => {
    return stateMapRef.current.get(sid) ?? null;
  }, []);

  return {
    sliceActive: currentState.sliceActive,
    sliceInfo: currentState.sliceInfo,
    sliceFromSpecs: currentState.sliceFromSpecs,
    sliceFilterMode: currentState.sliceFilterMode,
    setSliceFilterMode,
    isSlicing,
    taintedSeqs: currentState.taintedSeqs,
    sliceStartSeq: currentState.sliceStartSeq,
    sliceEndSeq: currentState.sliceEndSeq,
    sliceSourceSeq: currentState.sliceSourceSeq,
    sliceDataOnly: currentState.sliceDataOnly,
    sliceDuration: currentState.sliceDuration,
    sliceError: currentState.sliceError,
    runSlice,
    clearSlice,
    getSliceStatus,
    removeSession,
    getStateForSession,
  };
}
