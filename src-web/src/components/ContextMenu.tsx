import { useRef, useEffect, useState, useLayoutEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";

interface ContextMenuProps {
  x: number;
  y: number;
  onClose: () => void;
  children: ReactNode;
  minWidth?: number;
}

/** 统一风格的右键上下文菜单 */
export default function ContextMenu({ x, y, onClose, children, minWidth = 180 }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y });

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [onClose]);

  // 渲染后测量实际尺寸，确保不超出视口
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    setPos({
      left: Math.min(x, window.innerWidth - rect.width - 8),
      top: Math.min(y, window.innerHeight - rect.height - 8),
    });
  }, [x, y]);

  const style: React.CSSProperties = {
    position: "fixed",
    left: pos.left,
    top: pos.top,
    background: "var(--bg-dialog)",
    border: "1px solid var(--border-color)",
    borderRadius: 6,
    boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
    zIndex: 10000,
    padding: "4px 0",
    minWidth,
  };

  // Portal 到 body，避免祖先 contain:paint 导致 fixed 定位失效
  return createPortal(<div ref={ref} style={style}>{children}</div>, document.body);
}

/** 右键菜单项 */
export function ContextMenuItem({ label, shortcut, disabled, onClick, checked }: {
  label: ReactNode;
  shortcut?: string;
  disabled?: boolean;
  onClick?: () => void;
  checked?: boolean;
}) {
  return (
    <div
      onClick={() => { if (!disabled && onClick) onClick(); }}
      onMouseEnter={(e) => { if (!disabled) (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
      style={{
        display: "flex",
        alignItems: "center",
        padding: "6px 12px",
        fontSize: 12,
        color: disabled ? "var(--text-secondary)" : "var(--text-primary)",
        cursor: disabled ? "default" : "pointer",
        whiteSpace: "nowrap",
        gap: 8,
      }}
    >
      {checked !== undefined && (
        <span style={{ width: 16, flexShrink: 0, textAlign: "center", fontSize: 11 }}>
          {checked ? "✓" : ""}
        </span>
      )}
      <span style={{ flex: 1 }}>{label}</span>
      {shortcut && (
        <span style={{ marginLeft: 16, fontSize: 11, color: "var(--text-secondary)" }}>{shortcut}</span>
      )}
    </div>
  );
}

/** 右键菜单分隔线 */
export function ContextMenuSeparator() {
  return <div style={{ height: 1, background: "var(--border-color)", margin: "4px 0" }} />;
}
