import { useSyncExternalStore } from "react";

// Module-level state (singleton per JS context / WebView window)
let _seq: number | null = null;
const _listeners = new Set<() => void>();
function _emit() { _listeners.forEach(l => l()); }

export const selectedSeqStore = {
  get: () => _seq,
  set: (seq: number | null) => {
    if (Object.is(_seq, seq)) return;
    _seq = seq;
    _emit();
  },
  subscribe: (listener: () => void) => {
    _listeners.add(listener);
    return () => { _listeners.delete(listener); };
  },
};

/** Subscribe to selectedSeq — re-renders on every change */
export function useSelectedSeq(): number | null {
  return useSyncExternalStore(selectedSeqStore.subscribe, selectedSeqStore.get);
}

/** Subscribe to whether selectedSeq is non-null — only re-renders on null↔non-null transitions */
export function useHasSelectedSeq(): boolean {
  return useSyncExternalStore(
    selectedSeqStore.subscribe,
    () => selectedSeqStore.get() !== null
  );
}
