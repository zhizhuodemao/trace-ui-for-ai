import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useSelectedSeq } from "../stores/selectedSeqStore";

const LEFT_REGS = [
  "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
  "X8", "X9", "X10", "X11", "X12", "X13", "X14",
];

const RIGHT_REGS = [
  "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22",
  "X23", "X24", "X25", "X26", "X27", "X28", "X29",
];

const BOTTOM_LEFT = ["LR", "NZCV"];
const BOTTOM_RIGHT = ["SP", "PC"];

// LR 显示名 → 后端返回的 key 名映射
const KEY_MAP: Record<string, string> = { LR: "X30" };

interface Props {
  selectedSeq?: number | null;
  isPhase2Ready: boolean;
  sessionId: string | null;
}

function RegRow({ name, value, changed, read, special }: { name: string; value: string; changed: boolean; read: boolean; special?: string }) {
  const nameColor = changed ? "var(--reg-changed)" : read ? "var(--reg-read)" : special ?? "var(--text-secondary)";
  const valColor = changed ? "var(--reg-changed)" : read ? "var(--reg-read)" : special ?? "var(--text-primary)";
  const valRef = useRef<HTMLSpanElement>(null);
  const handleDoubleClick = useCallback(() => {
    navigator.clipboard.writeText(value);
    // 闪烁反馈
    const el = valRef.current;
    if (el) {
      el.style.transition = "background 0.15s";
      el.style.background = "rgba(80,200,120,0.3)";
      setTimeout(() => { el.style.background = "transparent"; }, 300);
    }
  }, [value]);
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "1px 0" }}>
      <span style={{ color: nameColor, width: 36, fontWeight: changed ? 600 : 400 }}>{name}</span>
      <span
        ref={valRef}
        style={{ color: valColor, fontWeight: changed ? 600 : 400, cursor: "text", userSelect: "text", borderRadius: 2 }}
        onDoubleClick={handleDoubleClick}
      >{value}</span>
    </div>
  );
}

export default function RegisterPanel({ selectedSeq: selectedSeqProp, isPhase2Ready, sessionId }: Props) {
  const selectedSeqFromStore = useSelectedSeq();
  const selectedSeq = selectedSeqProp !== undefined ? selectedSeqProp : selectedSeqFromStore;
  const [regs, setRegs] = useState<Record<string, string>>({});
  const [displaySeq, setDisplaySeq] = useState<number | null>(null);

  useEffect(() => {
    if (selectedSeq === null || !isPhase2Ready || !sessionId) {
      setRegs({});
      setDisplaySeq(null);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      invoke<Record<string, string>>("get_registers_at", { sessionId, seq: selectedSeq })
        .then((r) => {
          if (cancelled) return;
          setRegs(r);
          setDisplaySeq(selectedSeq);
        })
        .catch(() => { if (!cancelled) setRegs({}); });
    }, 30);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [selectedSeq, isPhase2Ready, sessionId]);

  const changedSet = useMemo(() => {
    const raw = regs["__changed"];
    if (!raw) return new Set<string>();
    return new Set(raw.split(","));
  }, [regs]);

  const readSet = useMemo(() => {
    const raw = regs["__read"];
    if (!raw) return new Set<string>();
    return new Set(raw.split(","));
  }, [regs]);

  const isChanged = (name: string) => {
    const key = KEY_MAP[name] ?? name;
    return changedSet.has(key);
  };

  const isRead = (name: string) => {
    const key = KEY_MAP[name] ?? name;
    return readSet.has(key);
  };

  const getVal = (name: string) => regs[KEY_MAP[name] ?? name] ?? "?";

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 8, background: "var(--bg-primary)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>
          Registers {displaySeq !== null ? `@ #${displaySeq + 1}` : ""}
        </span>
      </div>
      {displaySeq === null ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", fontSize: 12 }}>
          {isPhase2Ready ? "" : ""}
        </div>
      ) : (
        <div style={{ fontSize: "var(--font-size-sm)" }}>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            <div style={{ flex: 1 }}>
              {LEFT_REGS.map((name) => (
                <RegRow key={name} name={name} value={getVal(name)} changed={isChanged(name)} read={isRead(name)} />
              ))}
            </div>
            <div style={{ flex: 1 }}>
              {RIGHT_REGS.map((name) => (
                <RegRow key={name} name={name} value={getVal(name)} changed={isChanged(name)} read={isRead(name)} />
              ))}
            </div>
          </div>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 4 }}>
            <div style={{ flex: 1 }}>
              {BOTTOM_LEFT.map((name) => (
                <RegRow key={name} name={name} value={getVal(name)} changed={isChanged(name)} read={isRead(name)} />
              ))}
            </div>
            <div style={{ flex: 1 }}>
              {BOTTOM_RIGHT.map((name) => (
                <RegRow key={name} name={name} value={getVal(name)} changed={isChanged(name)} read={isRead(name)}
                  special={name === "PC" ? "var(--reg-pc)" : undefined} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
