import type React from "react";

interface ConfirmDialogProps {
  title: string;
  message: string | React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  onConfirm?: () => void;
  onCancel: () => void;
  confirmColor?: string;
  minWidth?: number;
  containerPadding?: string;
  containerStyle?: React.CSSProperties;
}

export default function ConfirmDialog({
  title,
  message,
  confirmText = "确定",
  cancelText = "取消",
  onConfirm,
  onCancel,
  confirmColor = "var(--btn-primary)",
  minWidth = 320,
  containerPadding = "24px 28px",
  containerStyle,
}: ConfirmDialogProps) {
  return (
    <div
      style={{
        position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex", alignItems: "center", justifyContent: "center",
        zIndex: 10000,
      }}
      onClick={onCancel}
    >
      <div
        style={{
          background: "var(--bg-dialog)",
          border: "1px solid var(--border-color)",
          borderRadius: 8,
          padding: containerPadding,
          minWidth: Math.min(minWidth, window.innerWidth - 40),
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
          ...containerStyle,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {typeof message === "string" ? (
          <>
            <div style={{ fontSize: 15, color: "var(--text-primary)", marginBottom: 8 }}>
              {title}
            </div>
            <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 20 }}>
              {message}
            </div>
          </>
        ) : (
          message
        )}
        <div style={{ display: "flex", justifyContent: "center", gap: 10 }}>
          <button
            onClick={onCancel}
            onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-secondary)"; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-input)"; }}
            style={{
              padding: onConfirm ? "6px 16px" : "6px 24px",
              background: "var(--bg-input)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            {onConfirm ? cancelText : "OK"}
          </button>
          {onConfirm && (
            <button
              onClick={onConfirm}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.opacity = "0.85"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.opacity = "1"; }}
              style={{
                padding: "6px 16px",
                background: confirmColor,
                color: "#fff",
                border: "none",
                borderRadius: 4,
                cursor: "pointer",
                fontSize: 13,
              }}
            >
              {confirmText}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
