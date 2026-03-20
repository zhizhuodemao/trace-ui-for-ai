/**
 * Canvas 颜色管理
 * Canvas 不支持 CSS var()，所有 Canvas 组件的颜色从 themeStore 获取。
 */

import { themeStore } from "../stores/themeStore";
import type { ThemeColors } from "../theme/themes";

function c(): ThemeColors { return themeStore.getColors(); }

// ── 共用颜色：TraceTable 和 Minimap 都用到的颜色值 ──
export function getSharedColors() {
  const t = c();
  return {
    bgPrimary: t.bgPrimary,
    borderColor: t.borderColor,
    textSecondary: t.textSecondary,
    textAddress: t.textAddress,
    textChanges: t.textChanges,
    asmMnemonic: t.asmMnemonic,
    asmRegister: t.asmRegister,
    asmMemory: t.asmMemory,
    asmImmediate: t.asmImmediate,
  };
}

// ── TraceTable 特有颜色 ──
export function getTraceTableColors() {
  const t = c();
  return {
    bgSecondary: t.bgSecondary,
    bgRowEven: t.bgRowEven,
    bgRowOdd: t.bgRowOdd,
    bgSelected: t.bgSelected,
    textPrimary: t.textPrimary,
    asmShift: t.asmShift,
    arrowAnchor: t.arrowAnchor,
    arrowDef: t.arrowDef,
    arrowUse: t.arrowUse,
    bgHover: t.bgHover,
    arrowAnchorBg: t.arrowAnchorBg,
    arrowDefBg: t.arrowDefBg,
    arrowUseBg: t.arrowUseBg,
    bgMultiSelect: t.bgMultiSelect,
    strikethroughLine: t.strikethroughLine,
    commentGutter: t.commentGutter,
    commentInline: t.commentInline,
    callInfoNormal: t.callInfoNormal,
    callInfoJni: t.callInfoJni,
    taintSourceMark: t.taintSourceMark,
    taintMark: t.taintMark,
  };
}

// ── Minimap 特有颜色 ──
export function getMinimapColors() {
  const t = c();
  return {
    selected: t.minimapSelected,
    viewportBg: t.minimapViewportBg,
    viewportHover: t.minimapViewportHover,
    viewportDrag: t.minimapViewportDrag,
    viewportBorder: t.minimapViewportBorder,
    summaryBg: t.minimapSummaryBg,
    hiddenBg: t.minimapHiddenBg,
  };
}

/* ── 向后兼容：静态常量仍可用，但值反映当前主题 ── */
/* 注意：这些是 getter，每次访问时返回当前主题的颜色 */
export const SHARED_COLORS = new Proxy({} as ReturnType<typeof getSharedColors>, {
  get: (_target, prop: string) => (getSharedColors() as Record<string, string>)[prop],
});

export const TRACE_TABLE_COLORS = new Proxy({} as ReturnType<typeof getTraceTableColors>, {
  get: (_target, prop: string) => (getTraceTableColors() as Record<string, string>)[prop],
});

export const MINIMAP_COLORS = new Proxy({} as ReturnType<typeof getMinimapColors>, {
  get: (_target, prop: string) => (getMinimapColors() as Record<string, string>)[prop],
});
