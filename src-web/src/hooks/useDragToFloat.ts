import { useCallback, useRef, useEffect } from "react";

const DRAG_THRESHOLD = 5;

interface UseDragToFloatOptions {
  onFloat: (id: string, pos: { x: number; y: number }) => void;
  onActivate: (id: string) => void;
}

/**
 * Unified drag-to-float hook.
 * Returns `startDrag(id, label, e)` — call it from onMouseDown.
 *  - id:    identifier (sessionId or panel key)
 *  - label: text shown in the ghost element
 *  - e:     the React mouse event
 */
export function useDragToFloat({ onFloat, onActivate }: UseDragToFloatOptions) {
  const dragState = useRef<{
    active: boolean;
    id: string;
    tabLabel: string;
    startX: number;
    startY: number;
    ghost: HTMLDivElement | null;
    removeListeners: (() => void) | null;
  } | null>(null);

  const cleanupDrag = useCallback(() => {
    const ds = dragState.current;
    if (!ds) return;
    if (ds.ghost) {
      document.body.removeChild(ds.ghost);
    }
    if (ds.removeListeners) {
      ds.removeListeners();
    }
    dragState.current = null;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  }, []);

  const startDrag = useCallback((id: string, label: string, e: React.MouseEvent) => {
    if (e.button !== 0) return; // left button only

    // 清理上一次未完成的拖拽状态（ghost + 事件监听器）
    cleanupDrag();

    const onMouseMove = (ev: MouseEvent) => {
      const ds = dragState.current;
      if (!ds) return;

      const dx = ev.clientX - ds.startX;
      const dy = ev.clientY - ds.startY;

      if (!ds.active) {
        if (Math.abs(dx) < DRAG_THRESHOLD && Math.abs(dy) < DRAG_THRESHOLD) return;
        ds.active = true;
        document.body.style.cursor = "grabbing";
        document.body.style.userSelect = "none";
        const ghost = document.createElement("div");
        ghost.textContent = ds.tabLabel;
        Object.assign(ghost.style, {
          position: "fixed",
          left: `${ev.clientX + 8}px`,
          top: `${ev.clientY - 12}px`,
          padding: "4px 14px",
          fontSize: "12px",
          background: "var(--bg-selected)",
          color: "var(--text-primary)",
          border: "1px solid var(--btn-primary)",
          borderRadius: "4px",
          opacity: "0.85",
          pointerEvents: "none",
          zIndex: "99999",
          whiteSpace: "nowrap",
        });
        document.body.appendChild(ghost);
        ds.ghost = ghost;
      } else if (ds.ghost) {
        ds.ghost.style.left = `${ev.clientX + 8}px`;
        ds.ghost.style.top = `${ev.clientY - 12}px`;
      }
    };

    const onMouseUp = (ev: MouseEvent) => {
      const ds = dragState.current;
      const wasActive = ds?.active;
      const dragId = ds?.id;
      cleanupDrag();
      if (wasActive && dragId) {
        onFloat(dragId, { x: ev.screenX, y: ev.screenY });
      } else if (dragId) {
        onActivate(dragId);
      }
    };

    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        cleanupDrag();
      }
    };

    const removeListeners = () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      document.removeEventListener("keydown", onKeyDown);
    };

    dragState.current = {
      active: false,
      id,
      tabLabel: label,
      startX: e.clientX,
      startY: e.clientY,
      ghost: null,
      removeListeners,
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    document.addEventListener("keydown", onKeyDown);
  }, [onFloat, onActivate, cleanupDrag]);

  // Cleanup on unmount
  useEffect(() => {
    return () => { cleanupDrag(); };
  }, [cleanupDrag]);

  return startDrag;
}
