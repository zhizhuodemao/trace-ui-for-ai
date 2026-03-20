import { memo } from "react";
import { REG_RE, SHIFT_RE, IMM_RE, BRACKET_RE, TOKEN_RE } from "../utils/arm64Tokens";
import { highlightText } from "../utils/highlightText";

function tokenColor(token: string, isFirst: boolean): string | undefined {
  if (isFirst) return "var(--asm-mnemonic)";
  if (BRACKET_RE.test(token)) return "var(--asm-memory)";
  if (IMM_RE.test(token)) return "var(--asm-immediate)";
  if (REG_RE.test(token)) return "var(--asm-register)";
  if (SHIFT_RE.test(token)) return "var(--asm-shift)";
  return undefined;
}

interface Props {
  text: string;
  onRegClick?: (regName: string) => void;
  activeReg?: string | null;
  highlightQuery?: string;
  caseSensitive?: boolean;
  fuzzy?: boolean;
  useRegex?: boolean;
}

function DisasmHighlight({ text, onRegClick, activeReg, highlightQuery, caseSensitive, fuzzy, useRegex }: Props) {
  if (!text) return null;

  const parts: { text: string; color?: string; isReg: boolean }[] = [];
  let lastIdx = 0;
  let isFirst = true;
  let match: RegExpExecArray | null;

  TOKEN_RE.lastIndex = 0;
  while ((match = TOKEN_RE.exec(text)) !== null) {
    if (match.index > lastIdx) {
      parts.push({ text: text.slice(lastIdx, match.index), isReg: false });
    }
    const color = tokenColor(match[0], isFirst);
    const isReg = !isFirst && REG_RE.test(match[0]);
    parts.push({ text: match[0], color, isReg });
    isFirst = false;
    lastIdx = TOKEN_RE.lastIndex;
  }
  if (lastIdx < text.length) {
    parts.push({ text: text.slice(lastIdx), isReg: false });
  }

  return (
    <>
      {parts.map((p, i) => {
        if (p.isReg && onRegClick) {
          const isActive = activeReg != null && p.text.toLowerCase() === activeReg.toLowerCase();
          return (
            <span
              key={i}
              onClick={(e) => { e.stopPropagation(); onRegClick(p.text); }}
              style={{
                color: p.color,
                cursor: "pointer",
                textDecoration: isActive ? "underline" : "none",
                textUnderlineOffset: 2,
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.textDecoration = "underline"; }}
              onMouseLeave={(e) => {
                if (!isActive) (e.currentTarget as HTMLElement).style.textDecoration = "none";
              }}
            >
              {highlightQuery ? highlightText(p.text, highlightQuery, caseSensitive ?? false, fuzzy ?? false, useRegex ?? false) : p.text}
            </span>
          );
        }
        return p.color
          ? <span key={i} style={{ color: p.color }}>{highlightQuery ? highlightText(p.text, highlightQuery, caseSensitive ?? false, fuzzy ?? false, useRegex ?? false) : p.text}</span>
          : <span key={i}>{highlightQuery ? highlightText(p.text, highlightQuery, caseSensitive ?? false, fuzzy ?? false, useRegex ?? false) : p.text}</span>;
      })}
    </>
  );
}

export default memo(DisasmHighlight);
