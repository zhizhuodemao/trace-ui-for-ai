import { useSyncExternalStore } from "react";
import type { ThemeId, ThemeColors } from "../theme/themes";
import { getTheme, THEMES } from "../theme/themes";

const THEME_KEY = "trace-ui-theme";
const VALID_IDS = new Set<string>(THEMES.map(t => t.id));

let _themeId: ThemeId = loadSaved();
let _colors: ThemeColors = getTheme(_themeId);
const _listeners = new Set<() => void>();
function _emit() { _listeners.forEach(l => l()); }

function loadSaved(): ThemeId {
  try {
    const v = localStorage.getItem(THEME_KEY);
    if (v && VALID_IDS.has(v)) return v as ThemeId;
  } catch { /* noop */ }
  return "dark";
}

/** Apply CSS variables and data-theme attribute to document */
function applyToDOM(id: ThemeId, colors: ThemeColors) {
  const root = document.documentElement;
  root.setAttribute("data-theme", id);

  const style = root.style;
  style.setProperty("--bg-primary", colors.bgPrimary);
  style.setProperty("--bg-secondary", colors.bgSecondary);
  style.setProperty("--bg-row-even", colors.bgRowEven);
  style.setProperty("--bg-row-odd", colors.bgRowOdd);
  style.setProperty("--bg-func-entry", colors.bgFuncEntry);
  style.setProperty("--bg-selected", colors.bgSelected);
  style.setProperty("--bg-tainted", colors.bgTainted);
  style.setProperty("--bg-input", colors.bgInput);
  style.setProperty("--bg-dialog", colors.bgDialog);

  style.setProperty("--text-primary", colors.textPrimary);
  style.setProperty("--text-secondary", colors.textSecondary);
  style.setProperty("--text-address", colors.textAddress);
  style.setProperty("--text-changes", colors.textChanges);
  style.setProperty("--text-ascii-printable", colors.textAsciiPrintable);
  style.setProperty("--text-ascii-nonprint", colors.textAsciiNonprint);
  style.setProperty("--text-hex-zero", colors.textHexZero);
  style.setProperty("--text-hex-highlight", colors.textHexHighlight);

  style.setProperty("--btn-primary", colors.btnPrimary);
  style.setProperty("--btn-taint", colors.btnTaint);

  style.setProperty("--reg-changed", colors.regChanged);
  style.setProperty("--reg-read", colors.regRead);
  style.setProperty("--reg-pc", colors.regPc);

  style.setProperty("--asm-mnemonic", colors.asmMnemonic);
  style.setProperty("--asm-register", colors.asmRegister);
  style.setProperty("--asm-memory", colors.asmMemory);
  style.setProperty("--asm-immediate", colors.asmImmediate);
  style.setProperty("--asm-shift", colors.asmShift);

  style.setProperty("--bg-hover", colors.bgHover);
  style.setProperty("--border-color", colors.borderColor);

  style.setProperty("--text-error", colors.textError);
  style.setProperty("--call-info-normal", colors.callInfoNormal);
  style.setProperty("--call-info-jni", colors.callInfoJni);

  style.setProperty("--scrollbar-thumb", colors.scrollbarThumb);
  style.setProperty("--scrollbar-thumb-hover", colors.scrollbarThumbHover);
}

export const themeStore = {
  get: (): ThemeId => _themeId,
  getColors: (): ThemeColors => _colors,

  set: (id: ThemeId) => {
    if (id === _themeId) return;
    _themeId = id;
    _colors = getTheme(id);
    localStorage.setItem(THEME_KEY, id);
    applyToDOM(id, _colors);
    _emit();
  },

  subscribe: (l: () => void) => {
    _listeners.add(l);
    return () => { _listeners.delete(l); };
  },

  /** Call once at app startup to apply saved theme */
  init: () => {
    applyToDOM(_themeId, _colors);
  },
};

/** React hook — returns current theme id */
export function useThemeId(): ThemeId {
  return useSyncExternalStore(themeStore.subscribe, themeStore.get);
}

/** React hook — returns current theme colors (for Canvas components) */
export function useThemeColors(): ThemeColors {
  return useSyncExternalStore(themeStore.subscribe, themeStore.getColors);
}
