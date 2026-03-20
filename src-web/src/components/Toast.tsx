import { useState, useCallback, useRef, useEffect } from "react";

type ToastType = "info" | "success" | "error";

interface ToastItem {
  id: number;
  message: string;
  type: ToastType;
}

const TOAST_COLORS: Record<ToastType, { border: string; icon: string }> = {
  success: { border: "#98c379", icon: "✓" },
  error: { border: "#e06c75", icon: "✗" },
  info: { border: "#528bff", icon: "ℹ" },
};

let nextId = 0;

export function useToast() {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const timersRef = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());

  const showToast = useCallback((message: string, options?: { duration?: number; type?: ToastType }) => {
    const { duration = 3000, type = "info" } = options ?? {};
    const id = nextId++;
    setToasts(prev => [...prev, { id, message, type }]);
    const timer = setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
      timersRef.current.delete(id);
    }, duration);
    timersRef.current.set(id, timer);
  }, []);

  useEffect(() => {
    return () => {
      timersRef.current.forEach(t => clearTimeout(t));
    };
  }, []);

  return { toasts, showToast };
}

export default function ToastContainer({ toasts }: { toasts: ToastItem[] }) {
  if (toasts.length === 0) return null;

  return (
    <div style={{
      position: "fixed",
      top: 44,
      left: "50%",
      transform: "translateX(-50%)",
      zIndex: 99999,
      display: "flex",
      flexDirection: "column",
      gap: 8,
      pointerEvents: "none",
    }}>
      {toasts.map(t => {
        const colors = TOAST_COLORS[t.type];
        return (
          <div key={t.id} style={{
            display: "flex",
            alignItems: "center",
            background: "var(--bg-dialog)",
            color: "var(--text-primary)",
            padding: "8px 16px 8px 0",
            borderRadius: 6,
            fontSize: 13,
            boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
            borderLeft: `3px solid ${colors.border}`,
            animation: "toast-slide-down 0.25s ease",
          }}>
            <span style={{
              color: colors.border,
              fontSize: 14,
              fontWeight: 700,
              width: 32,
              textAlign: "center",
              flexShrink: 0,
            }}>
              {colors.icon}
            </span>
            {t.message}
          </div>
        );
      })}
      <style>{`
        @keyframes toast-slide-down {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
