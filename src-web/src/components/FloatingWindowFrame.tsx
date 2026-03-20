import { useState, useCallback } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import WindowControls from "./WindowControls";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";
import { isMac } from "../utils/platform";

interface FloatingWindowFrameProps {
  title: React.ReactNode;
  children: React.ReactNode;
  onClose?: () => void;
  /** 标题栏右侧额外控件（位于 pin 按钮左侧） */
  titleBarExtra?: React.ReactNode;
}

export default function FloatingWindowFrame({ title, children, onClose, titleBarExtra }: FloatingWindowFrameProps) {
  // 置顶锁定
  const [isPinned, setIsPinned] = useState(false);
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);

  const togglePin = useCallback(() => {
    setIsPinned(prev => {
      const next = !prev;
      getCurrentWindow().setAlwaysOnTop(next);
      return next;
    });
  }, []);

  return (
    <div style={{
      height: "100vh",
      display: "flex",
      flexDirection: "column",
      background: "var(--bg-primary)",
      color: "var(--text-primary)",
      borderRadius: 8,
      overflow: "hidden",
    }}>
      {/* 顶部标题栏 */}
      <div
        data-tauri-drag-region
        onContextMenu={(e) => {
          e.preventDefault();
          setCtxMenu({ x: e.clientX, y: e.clientY });
        }}
        style={{
          display: "flex",
          alignItems: "center",
          padding: isMac ? "0 8px 0 0" : "0 0 0 12px",
          height: 36,
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
          fontSize: 13,
          fontWeight: 600,
          gap: 8,
        }}
      >
        {isMac && <WindowControls />}
        <span
          data-tauri-drag-region
          style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        >
          {title}
        </span>
        {titleBarExtra}
        <span
          onClick={togglePin}
          title={isPinned ? "Unpin (disable always on top)" : "Pin (always on top)"}
          style={{
            cursor: "pointer",
            fontSize: 14,
            color: isPinned ? "var(--btn-primary)" : "var(--text-secondary)",
            transform: isPinned ? "rotate(-45deg)" : "none",
            transition: "transform 0.2s, color 0.2s",
            userSelect: "none",
            lineHeight: 1,
          }}
        >{"\uD83D\uDCCC"}</span>
        {!isMac && <WindowControls />}
      </div>

      {/* 右键上下文菜单 */}
      {ctxMenu && (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} onClose={() => setCtxMenu(null)} minWidth={160}>
          <ContextMenuItem
            label="Always on Top"
            checked={isPinned}
            onClick={() => { togglePin(); setCtxMenu(null); }}
          />
        </ContextMenu>
      )}

      {/* 内容区域 */}
      {children}
    </div>
  );
}
