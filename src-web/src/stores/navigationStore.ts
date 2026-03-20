import { useSyncExternalStore } from "react";
import { selectedSeqStore } from "./selectedSeqStore";

const MAX_HISTORY = 300;
let _history: number[] = [];
let _currentIndex = -1;
const _listeners = new Set<() => void>();
function _emit() { _listeners.forEach(l => l()); }

export const navigationStore = {
  navigate: (seq: number) => {
    const base = _history.slice(0, _currentIndex + 1);
    const next = [...base, seq];
    if (next.length > MAX_HISTORY) {
      _history = next.slice(next.length - MAX_HISTORY);
      _currentIndex = _history.length - 1;
    } else {
      _history = next;
      _currentIndex = next.length - 1;
    }
    selectedSeqStore.set(seq);
    _emit();
  },

  goBack: () => {
    if (_currentIndex <= 0) return;
    _currentIndex--;
    selectedSeqStore.set(_history[_currentIndex]);
    _emit();
  },

  goForward: () => {
    if (_currentIndex >= _history.length - 1) return;
    _currentIndex++;
    selectedSeqStore.set(_history[_currentIndex]);
    _emit();
  },

  getCanGoBack: () => _currentIndex > 0,
  getCanGoForward: () => _currentIndex < _history.length - 1,
  subscribe: (l: () => void) => { _listeners.add(l); return () => { _listeners.delete(l); }; },
  reset: () => { _history = []; _currentIndex = -1; _emit(); },
};

/** Re-renders only when canGoBack boolean changes */
export function useCanGoBack(): boolean {
  return useSyncExternalStore(navigationStore.subscribe, navigationStore.getCanGoBack);
}

/** Re-renders only when canGoForward boolean changes */
export function useCanGoForward(): boolean {
  return useSyncExternalStore(navigationStore.subscribe, navigationStore.getCanGoForward);
}
