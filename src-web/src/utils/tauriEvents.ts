/**
 * Cleanup an array of Tauri event unlisteners.
 * Usage: return () => cleanupListeners(unlisteners);
 */
export function cleanupListeners(unlisteners: Promise<() => void>[]) {
  unlisteners.forEach(p => p.then(fn => fn()));
}

/**
 * Cleanup a single Tauri event unlistener.
 * Usage: return () => cleanupListener(unlisten);
 */
export function cleanupListener(unlisten: Promise<() => void>) {
  unlisten.then(fn => fn());
}
