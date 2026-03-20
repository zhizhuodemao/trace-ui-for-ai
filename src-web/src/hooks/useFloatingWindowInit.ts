import { useState, useEffect } from "react";
import { emit, listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { cleanupListener } from "../utils/tauriEvents";

/**
 * Hook for floating window initialization protocol.
 * 1. Registers a listener for `{channel}:init-data`
 * 2. Emits `{channel}:ready:{winLabel}` to notify the parent
 * 3. Parent sends data via emitTo, which is received by the listener
 *
 * @param channel - Event channel name (e.g. "string-detail", "xrefs", "call-info")
 * @returns The received data, or null if not yet received
 */
export function useFloatingWindowInit<T>(channel: string): T | null {
  const [data, setData] = useState<T | null>(null);

  useEffect(() => {
    const unlisten = listen<T>(`${channel}:init-data`, (e) => {
      setData(e.payload);
    });
    const winLabel = getCurrentWindow().label;
    emit(`${channel}:ready:${winLabel}`);
    return () => { cleanupListener(unlisten); };
  }, [channel]);

  return data;
}
