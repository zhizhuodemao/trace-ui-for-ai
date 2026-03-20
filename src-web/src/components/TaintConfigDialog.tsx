import React, { useState, useCallback, useRef } from "react";
import { createPortal } from "react-dom";

interface TaintSource {
  id: number;
  type: "register" | "memory";
  register: string;
  memAddr: string;
  memSize: string;
}

interface Props {
  seq: number;
  totalLines: number;
  defaultDefs?: string[];
  defaultMemAddr?: string;
  onExecute: (fromSpecs: string[], startSeq?: number, endSeq?: number, dataOnly?: boolean) => void;
  onClose: () => void;
}

const REGISTERS = [
  "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
  "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
  "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
];

const MEM_SIZES = ["1", "2", "4", "8", "16"];

function normalizeReg(token: string): string {
  const t = token.toLowerCase();
  const wMatch = t.match(/^w(\d+)$/);
  if (wMatch) return `x${wMatch[1]}`;
  return t;
}

function createDefaultSources(
  nextIdRef: React.MutableRefObject<number>,
  defaultDefs?: string[],
  defaultMemAddr?: string,
): TaintSource[] {
  const sources: TaintSource[] = [];
  if (defaultDefs && defaultDefs.length > 0) {
    for (const reg of defaultDefs) {
      const normalized = normalizeReg(reg);
      if (!REGISTERS.includes(normalized)) continue;
      sources.push({
        id: nextIdRef.current++,
        type: "register",
        register: normalized,
        memAddr: "",
        memSize: "4",
      });
    }
  }
  if (defaultMemAddr) {
    sources.push({
      id: nextIdRef.current++,
      type: "memory",
      register: "x0",
      memAddr: defaultMemAddr,
      memSize: "4",
    });
  }
  if (sources.length === 0) {
    sources.push({
      id: nextIdRef.current++,
      type: "register",
      register: "x0",
      memAddr: "",
      memSize: "4",
    });
  }
  return sources;
}

// ── Shared styles ──

const cardStyle: React.CSSProperties = {
  background: "var(--bg-input)",
  border: "1px solid var(--border-color)",
  borderRadius: 8,
  padding: "10px 14px",
};

const labelStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-secondary)",
  marginBottom: 4,
  display: "block",
};

const fieldInputStyle: React.CSSProperties = {
  background: "transparent",
  border: "none",
  color: "var(--text-primary)",
  fontSize: 14,
  outline: "none",
  width: "100%",
  padding: 0,
  fontFamily: "var(--font-mono)",
};

const fieldSelectStyle: React.CSSProperties = {
  ...fieldInputStyle,
  cursor: "pointer",
  appearance: "auto" as React.CSSProperties["appearance"],
};

export default function TaintConfigDialog({
  seq,
  totalLines,
  defaultDefs,
  defaultMemAddr,
  onExecute,
  onClose,
}: Props) {
  const nextIdRef = useRef(1);
  const [startSeq, setStartSeq] = useState("1");
  const [endSeq, setEndSeq] = useState(String(seq + 1));
  const [controlDep, setControlDep] = useState(true);
  const [controlTip, setControlTip] = useState<{ x: number; y: number } | null>(null);
  const controlTipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [sources, setSources] = useState<TaintSource[]>(() =>
    createDefaultSources(nextIdRef, defaultDefs, defaultMemAddr)
  );

  const addSource = useCallback(() => {
    setSources(prev => [
      ...prev,
      {
        id: nextIdRef.current++,
        type: "register",
        register: "x0",
        memAddr: "",
        memSize: "4",
      },
    ]);
  }, []);

  const removeSource = useCallback((id: number) => {
    setSources(prev => prev.length > 1 ? prev.filter(s => s.id !== id) : prev);
  }, []);

  const updateSource = useCallback((id: number, updates: Partial<TaintSource>) => {
    setSources(prev =>
      prev.map(s => (s.id === id ? { ...s, ...updates } : s))
    );
  }, []);

  const handleExecute = useCallback(() => {
    // sourceLineNum: 污点源所在行号（1-based），来自右键点击的行
    const sourceLineNum = seq + 1;

    const specs: string[] = [];
    for (const src of sources) {
      if (src.type === "register") {
        specs.push(`reg:${src.register}@${sourceLineNum}`);
      } else {
        const addr = src.memAddr.trim();
        if (!addr) continue;
        const sizeNum = parseInt(src.memSize, 10);
        specs.push(`mem:${addr}:${sizeNum}@${sourceLineNum}`);
      }
    }

    if (specs.length > 0) {
      // Start Seq / End Seq 纯粹是范围过滤器，与污点源行号分离
      const parsedStartSeq = startSeq.trim() ? parseInt(startSeq.trim(), 10) : undefined;
      const validStartSeq = parsedStartSeq && !isNaN(parsedStartSeq) && parsedStartSeq >= 1
        ? parsedStartSeq - 1
        : undefined;
      const parsedEndSeq = endSeq.trim() ? parseInt(endSeq.trim(), 10) : undefined;
      const validEndSeq = parsedEndSeq && !isNaN(parsedEndSeq) && parsedEndSeq >= 1
        ? parsedEndSeq - 1
        : undefined;
      onExecute(specs, validStartSeq, validEndSeq, !controlDep);
    }
  }, [seq, startSeq, endSeq, sources, controlDep, onExecute]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    } else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      handleExecute();
    }
  }, [onClose, handleExecute]);

  return (
    <>
    <div
      style={{
        position: "fixed",
        top: 0, left: 0, right: 0, bottom: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 10000,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      onKeyDown={handleKeyDown}
    >
      <div
        style={{
          background: "var(--bg-dialog)",
          border: "1px solid var(--border-color)",
          borderRadius: 12,
          boxShadow: "0 12px 40px rgba(0,0,0,0.5)",
          padding: "28px 32px",
          width: Math.min(560, window.innerWidth - 40),
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Title + Close ── */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text-primary)" }}>
            Taint Analysis Configuration
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent", border: "none",
              color: "var(--text-secondary)", fontSize: 18,
              cursor: "pointer", padding: "0 2px", lineHeight: 1,
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--text-primary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-secondary)"; }}
          >
            ×
          </button>
        </div>

        {/* ── Start Seq / End Seq ── */}
        <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
          <div style={{ ...cardStyle, flex: 1 }}>
            <label style={labelStyle}>Start Seq</label>
            <input
              type="text"
              value={startSeq}
              onChange={(e) => setStartSeq(e.target.value)}
              style={fieldInputStyle}
            />
          </div>
          <div style={{ ...cardStyle, flex: 1 }}>
            <label style={labelStyle}>End Seq</label>
            <input
              type="text"
              value={endSeq}
              onChange={(e) => setEndSeq(e.target.value)}
              placeholder="to end"
              style={fieldInputStyle}
            />
          </div>
        </div>

        {/* ── Dependency Options ── */}
        <div style={{ ...cardStyle, marginBottom: 24, display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)", flexShrink: 0 }}>
            Dependencies
          </div>
          <label
            style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", fontSize: 13, color: "var(--text-primary)" }}
            onMouseEnter={(e) => {
              const mx = e.clientX, my = e.clientY;
              controlTipTimer.current = setTimeout(() => setControlTip({ x: mx, y: my + 16 }), 100);
            }}
            onMouseLeave={() => {
              if (controlTipTimer.current) { clearTimeout(controlTipTimer.current); controlTipTimer.current = null; }
              setControlTip(null);
            }}
          >
            <input
              type="checkbox"
              checked={controlDep}
              onChange={(e) => setControlDep(e.target.checked)}
              style={{ accentColor: "var(--btn-primary)" }}
            />
            Control
          </label>
        </div>

        {/* ── Taint Sources Header ── */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>
            Taint Sources
          </div>
          <button
            onClick={addSource}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-secondary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            style={{
              background: "transparent",
              border: "1px solid var(--border-color)",
              borderRadius: 6,
              color: "var(--text-primary)",
              padding: "5px 14px",
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            + Add Symbol
          </button>
        </div>

        {/* ── Sources List ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 28 }}>
          {sources.map((src) => (
            <div key={src.id} style={{ ...cardStyle, display: "flex", alignItems: "flex-end", gap: 12 }}>
              {/* Type */}
              <div style={{ width: 110, flexShrink: 0 }}>
                <label style={labelStyle}>Type</label>
                <select
                  value={src.type}
                  onChange={(e) => updateSource(src.id, { type: e.target.value as "register" | "memory" })}
                  style={{ ...fieldSelectStyle, fontSize: 14 }}
                >
                  <option value="register">Register</option>
                  <option value="memory">Memory</option>
                </select>
              </div>

              {/* Value field */}
              {src.type === "register" ? (
                <div style={{ flex: 1 }}>
                  <label style={labelStyle}>Register</label>
                  <select
                    value={src.register}
                    onChange={(e) => updateSource(src.id, { register: e.target.value })}
                    style={{ ...fieldSelectStyle, fontSize: 14, textTransform: "uppercase" }}
                  >
                    {REGISTERS.map((r) => (
                      <option key={r} value={r}>{r.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
              ) : (
                <>
                  <div style={{ flex: 1 }}>
                    <label style={labelStyle}>Address</label>
                    <input
                      type="text"
                      value={src.memAddr}
                      onChange={(e) => updateSource(src.id, { memAddr: e.target.value })}
                      placeholder="0x..."
                      style={{ ...fieldInputStyle, fontSize: 14 }}
                    />
                  </div>
                  <div style={{ width: 60, flexShrink: 0 }}>
                    <label style={labelStyle}>Size</label>
                    <select
                      value={src.memSize}
                      onChange={(e) => updateSource(src.id, { memSize: e.target.value })}
                      style={{ ...fieldSelectStyle, fontSize: 14 }}
                    >
                      {MEM_SIZES.map((s) => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                  </div>
                </>
              )}

              {/* Delete */}
              <button
                onClick={() => removeSource(src.id)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: sources.length > 1 ? "var(--reg-changed)" : "var(--text-secondary)",
                  cursor: sources.length > 1 ? "pointer" : "default",
                  fontSize: 16,
                  padding: "0 2px",
                  lineHeight: 1,
                  flexShrink: 0,
                  opacity: sources.length > 1 ? 1 : 0.3,
                }}
                disabled={sources.length <= 1}
              >
                ×
              </button>
            </div>
          ))}
        </div>

        {/* ── Buttons ── */}
        <div style={{ display: "flex", justifyContent: "center", gap: 10 }}>
          <button
            onClick={onClose}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-secondary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-input)"; }}
            style={{
              padding: "6px 16px",
              background: "var(--bg-input)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleExecute}
            onMouseEnter={(e) => { e.currentTarget.style.opacity = "0.85"; }}
            onMouseLeave={(e) => { e.currentTarget.style.opacity = "1"; }}
            style={{
              padding: "6px 16px",
              background: "var(--btn-primary)",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            Run Analysis
          </button>
        </div>
      </div>
    </div>
    {controlTip && createPortal(
      <div style={{
        position: "fixed", left: controlTip.x, top: controlTip.y,
        background: "var(--bg-dialog)", color: "var(--text-primary)",
        border: "1px solid var(--border-color)", borderRadius: 4,
        padding: "4px 8px", fontSize: 11, maxWidth: 320, lineHeight: 1.5,
        pointerEvents: "none", zIndex: 10002,
        boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
      }}>
        When enabled, taint propagates through control-flow dependencies (e.g. conditional branches), not just data-flow. This may increase the number of tainted instructions.
      </div>,
      document.body,
    )}
    </>
  );
}
