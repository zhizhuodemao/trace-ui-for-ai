import { getCurrentWindow } from "@tauri-apps/api/window";
import { useCallback, useState, useEffect } from "react";
import { isMac } from "../utils/platform";

// macOS 红绿灯颜色
const MAC_COLORS = {
  close: { bg: "#ff5f57", icon: "#4d0000" },
  minimize: { bg: "#febc2e", icon: "#5a3e00" },
  maximize: { bg: "#28c840", icon: "#003a00" },
};
const MAC_INACTIVE = "#3d3d3d";

function MacTrafficLights() {
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(true);

  useEffect(() => {
    const onFocus = () => setFocused(true);
    const onBlur = () => setFocused(false);
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);
    return () => { window.removeEventListener("focus", onFocus); window.removeEventListener("blur", onBlur); };
  }, []);

  const handleClose = useCallback(() => getCurrentWindow().close(), []);
  const handleMinimize = useCallback(() => getCurrentWindow().minimize(), []);
  const handleMaximize = useCallback(() => getCurrentWindow().toggleMaximize(), []);

  const buttons = [
    { id: "close" as const, action: handleClose, icon: "×" },
    { id: "minimize" as const, action: handleMinimize, icon: "−" },
    { id: "maximize" as const, action: handleMaximize, icon: "+" },
  ];

  return (
    <div
      style={{ display: "flex", gap: 8, alignItems: "center", padding: "0 8px", flexShrink: 0 }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      {buttons.map(({ id, action, icon }) => (
        <div
          key={id}
          onClick={action}
          style={{
            width: 12,
            height: 12,
            borderRadius: "50%",
            background: focused ? MAC_COLORS[id].bg : MAC_INACTIVE,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            fontSize: 9,
            fontWeight: 700,
            lineHeight: 1,
            color: hovered ? MAC_COLORS[id].icon : "transparent",
          }}
        >
          {icon}
        </div>
      ))}
    </div>
  );
}

function WinControls() {
  const [hovered, setHovered] = useState<string | null>(null);

  const handleMinimize = useCallback(() => getCurrentWindow().minimize(), []);
  const handleToggleMaximize = useCallback(() => getCurrentWindow().toggleMaximize(), []);
  const handleClose = useCallback(() => getCurrentWindow().close(), []);

  const btnStyle = (id: string): React.CSSProperties => ({
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    width: 46,
    height: "100%",
    border: "none",
    background:
      hovered === id
        ? id === "close"
          ? "#e81123"
          : "var(--bg-selected)"
        : "transparent",
    color:
      hovered === "close" && id === "close"
        ? "#ffffff"
        : "var(--text-secondary)",
    cursor: "pointer",
    padding: 0,
  });

  return (
    <div style={{ display: "flex", height: "100%", flexShrink: 0 }}>
      <button
        style={btnStyle("minimize")}
        onClick={handleMinimize}
        onMouseEnter={() => setHovered("minimize")}
        onMouseLeave={() => setHovered(null)}
        aria-label="Minimize"
      >
        <svg width="10" height="1" viewBox="0 0 10 1">
          <rect fill="currentColor" width="10" height="1" />
        </svg>
      </button>
      <button
        style={btnStyle("maximize")}
        onClick={handleToggleMaximize}
        onMouseEnter={() => setHovered("maximize")}
        onMouseLeave={() => setHovered(null)}
        aria-label="Maximize"
      >
        <svg width="10" height="10" viewBox="0 0 10 10">
          <rect fill="none" stroke="currentColor" strokeWidth="1" x="0.5" y="0.5" width="9" height="9" />
        </svg>
      </button>
      <button
        style={btnStyle("close")}
        onClick={handleClose}
        onMouseEnter={() => setHovered("close")}
        onMouseLeave={() => setHovered(null)}
        aria-label="Close"
      >
        <svg width="10" height="10" viewBox="0 0 10 10">
          <line x1="0" y1="0" x2="10" y2="10" stroke="currentColor" strokeWidth="1.2" />
          <line x1="10" y1="0" x2="0" y2="10" stroke="currentColor" strokeWidth="1.2" />
        </svg>
      </button>
    </div>
  );
}

export default function WindowControls() {
  return isMac ? <MacTrafficLights /> : <WinControls />;
}
