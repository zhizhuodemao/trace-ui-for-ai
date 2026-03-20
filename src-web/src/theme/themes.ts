/**
 * 主题颜色定义
 * 所有主题的颜色集中在此文件管理，包括 CSS 变量和 Canvas 颜色。
 */

export type ThemeId =
  | "dark" | "light" | "dim"
  | "monokai" | "dracula" | "nord" | "catppuccin-mocha" | "catppuccin-latte"
  | "gruvbox-dark" | "tokyo-night" | "solarized-dark" | "solarized-light"
  | "github-light" | "high-contrast";

export interface ThemeColors {
  /* ── CSS 变量映射 ── */
  bgPrimary: string;
  bgSecondary: string;
  bgRowEven: string;
  bgRowOdd: string;
  bgFuncEntry: string;
  bgSelected: string;
  bgTainted: string;
  bgInput: string;
  bgDialog: string;

  textPrimary: string;
  textSecondary: string;
  textAddress: string;
  textChanges: string;
  textAsciiPrintable: string;
  textAsciiNonprint: string;
  textHexZero: string;
  textHexHighlight: string;

  btnPrimary: string;
  btnTaint: string;

  regChanged: string;
  regRead: string;
  regPc: string;

  asmMnemonic: string;
  asmRegister: string;
  asmMemory: string;
  asmImmediate: string;
  asmShift: string;

  borderColor: string;

  scrollbarThumb: string;
  scrollbarThumbHover: string;

  /* ── Canvas 特有颜色 ── */
  // TraceTable
  arrowAnchor: string;
  arrowDef: string;
  arrowUse: string;
  bgHover: string;
  arrowAnchorBg: string;
  arrowDefBg: string;
  arrowUseBg: string;
  bgMultiSelect: string;
  strikethroughLine: string;
  commentGutter: string;
  commentInline: string;
  callInfoNormal: string;
  callInfoJni: string;
  taintSourceMark: string;
  taintMark: string;
  textError: string;

  // Minimap
  minimapSelected: string;
  minimapSummaryBg: string;
  minimapHiddenBg: string;
  minimapViewportBg: string;
  minimapViewportHover: string;
  minimapViewportDrag: string;
  minimapViewportBorder: string;
}

export interface ThemeMeta {
  id: ThemeId;
  label: string;
  group: "dark" | "light";
  colors: ThemeColors;
}

/* ── helpers for dark/light theme canvas defaults ── */
const DARK_CANVAS_DEFAULTS = {
  bgHover: "rgba(255,255,255,0.04)",
  arrowAnchorBg: "rgba(255,255,255,0.08)",
  bgMultiSelect: "rgba(80,200,120,0.18)",
  minimapViewportBg: "rgba(255,255,255,0.08)",
  minimapViewportHover: "rgba(255,255,255,0.15)",
  minimapViewportDrag: "rgba(255,255,255,0.20)",
  minimapViewportBorder: "rgba(255,255,255,0.2)",
  minimapSummaryBg: "rgba(198, 120, 221, 0.15)",
  minimapHiddenBg: "rgba(136, 136, 136, 0.10)",
  taintSourceMark: "#fab387",
  taintMark: "#a6e3a1",
  textError: "#e06c75",
};

const LIGHT_CANVAS_DEFAULTS = {
  bgHover: "rgba(0,0,0,0.04)",
  arrowAnchorBg: "rgba(224,48,48,0.08)",
  bgMultiSelect: "rgba(80,200,120,0.15)",
  minimapViewportBg: "rgba(0,0,0,0.06)",
  minimapViewportHover: "rgba(0,0,0,0.12)",
  minimapViewportDrag: "rgba(0,0,0,0.18)",
  minimapViewportBorder: "rgba(0,0,0,0.2)",
  minimapSummaryBg: "rgba(136, 56, 188, 0.12)",
  minimapHiddenBg: "rgba(100, 100, 100, 0.10)",
  taintSourceMark: "#d75f00",
  taintMark: "#2e8b57",
  textError: "#e45649",
};

/* ═══════════════════════════════════════════════════════════
   Dark — One Dark Trace (default)
   ═══════════════════════════════════════════════════════════ */
const dark: ThemeColors = {
  bgPrimary: "#1e1f22",
  bgSecondary: "#27282c",
  bgRowEven: "#1e1f22",
  bgRowOdd: "#222327",
  bgFuncEntry: "#1e2a38",
  bgSelected: "#2c3e5c",
  bgTainted: "#3a1e32",
  bgInput: "#2c2d31",
  bgDialog: "#1a1b1e",

  textPrimary: "#abb2bf",
  textSecondary: "#636d83",
  textAddress: "#61afef",
  textChanges: "#e5c07b",
  textAsciiPrintable: "#98c379",
  textAsciiNonprint: "#3e4150",
  textHexZero: "#3e4150",
  textHexHighlight: "#e5c07b",

  btnPrimary: "#528bff",
  btnTaint: "#d19a66",

  regChanged: "#e06c75",
  regRead: "#61afef",
  regPc: "#61afef",

  asmMnemonic: "#c678dd",
  asmRegister: "#56b6c2",
  asmMemory: "#e5c07b",
  asmImmediate: "#d19a66",
  asmShift: "#98c379",

  borderColor: "#3e4150",

  scrollbarThumb: "#3e4150",
  scrollbarThumbHover: "#525769",

  arrowAnchor: "#e05050",
  arrowDef: "#4caf50",
  arrowUse: "#5c9fd6",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(76,175,80,0.12)",
  arrowUseBg: "rgba(92,159,214,0.12)",
  strikethroughLine: "#888888",
  commentGutter: "rgba(230,160,50,0.8)",
  commentInline: "#8b95a7",
  callInfoNormal: "#e06c75",
  callInfoJni: "#d16d9e",

  minimapSelected: "rgba(44, 62, 92, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Light — 浅白色主题
   ═══════════════════════════════════════════════════════════ */
const light: ThemeColors = {
  bgPrimary: "#f5f5f5",
  bgSecondary: "#eaeaeb",
  bgRowEven: "#f5f5f5",
  bgRowOdd: "#efefef",
  bgFuncEntry: "#dce8f5",
  bgSelected: "#c4d7f2",
  bgTainted: "#f5dce8",
  bgInput: "#ffffff",
  bgDialog: "#f0f0f0",

  textPrimary: "#383a42",
  textSecondary: "#8c919a",
  textAddress: "#4078f2",
  textChanges: "#c18401",
  textAsciiPrintable: "#50a14f",
  textAsciiNonprint: "#c8cad0",
  textHexZero: "#c8cad0",
  textHexHighlight: "#c18401",

  btnPrimary: "#4078f2",
  btnTaint: "#c18401",

  regChanged: "#e45649",
  regRead: "#4078f2",
  regPc: "#4078f2",

  asmMnemonic: "#a626a4",
  asmRegister: "#0184bc",
  asmMemory: "#c18401",
  asmImmediate: "#986801",
  asmShift: "#50a14f",

  borderColor: "#d0d0d0",

  scrollbarThumb: "#c0c0c0",
  scrollbarThumbHover: "#a0a0a0",

  arrowAnchor: "#e03030",
  arrowDef: "#3d9140",
  arrowUse: "#4078f2",
  ...LIGHT_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(61,145,64,0.10)",
  arrowUseBg: "rgba(64,120,242,0.10)",
  strikethroughLine: "#999999",
  commentGutter: "rgba(193,132,1,0.7)",
  commentInline: "#6a6f78",
  callInfoNormal: "#e45649",
  callInfoJni: "#a626a4",

  minimapSelected: "rgba(196, 215, 242, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Dim — 柔和深色（比 Dark 更低对比度，护眼）
   ═══════════════════════════════════════════════════════════ */
const dim: ThemeColors = {
  bgPrimary: "#282c34",
  bgSecondary: "#2e323b",
  bgRowEven: "#282c34",
  bgRowOdd: "#2b3039",
  bgFuncEntry: "#253345",
  bgSelected: "#35485e",
  bgTainted: "#3d2637",
  bgInput: "#333842",
  bgDialog: "#242830",

  textPrimary: "#9da5b4",
  textSecondary: "#5c6370",
  textAddress: "#5cacee",
  textChanges: "#d4a955",
  textAsciiPrintable: "#8fbc6f",
  textAsciiNonprint: "#3e4452",
  textHexZero: "#3e4452",
  textHexHighlight: "#d4a955",

  btnPrimary: "#4d78cc",
  btnTaint: "#c49060",

  regChanged: "#d46a6a",
  regRead: "#5cacee",
  regPc: "#5cacee",

  asmMnemonic: "#b07cd8",
  asmRegister: "#4db8b0",
  asmMemory: "#d4a955",
  asmImmediate: "#c49060",
  asmShift: "#8fbc6f",

  borderColor: "#3e4452",

  scrollbarThumb: "#3e4452",
  scrollbarThumbHover: "#4b5263",

  arrowAnchor: "#d46a6a",
  arrowDef: "#4caf50",
  arrowUse: "#5cacee",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(76,175,80,0.10)",
  arrowUseBg: "rgba(92,159,214,0.10)",
  bgHover: "rgba(255,255,255,0.03)",
  bgMultiSelect: "rgba(80,200,120,0.14)",
  strikethroughLine: "#777777",
  commentGutter: "rgba(210,150,50,0.7)",
  commentInline: "#7a8494",
  callInfoNormal: "#d46a6a",
  callInfoJni: "#b07cd8",

  minimapSelected: "rgba(53, 72, 94, 0.6)",
  minimapViewportBg: "rgba(255,255,255,0.06)",
  minimapViewportHover: "rgba(255,255,255,0.12)",
  minimapViewportDrag: "rgba(255,255,255,0.18)",
  minimapViewportBorder: "rgba(255,255,255,0.2)",
};

/* ═══════════════════════════════════════════════════════════
   Monokai — Sublime Text 经典配色
   ═══════════════════════════════════════════════════════════ */
const monokai: ThemeColors = {
  bgPrimary: "#272822",
  bgSecondary: "#2d2e27",
  bgRowEven: "#272822",
  bgRowOdd: "#2c2d26",
  bgFuncEntry: "#2e3428",
  bgSelected: "#49483e",
  bgTainted: "#3e2832",
  bgInput: "#3e3d32",
  bgDialog: "#1e1f1c",

  textPrimary: "#f8f8f2",
  textSecondary: "#75715e",
  textAddress: "#66d9ef",
  textChanges: "#e6db74",
  textAsciiPrintable: "#a6e22e",
  textAsciiNonprint: "#3e3d32",
  textHexZero: "#3e3d32",
  textHexHighlight: "#e6db74",

  btnPrimary: "#a6e22e",
  btnTaint: "#fd971f",

  regChanged: "#f92672",
  regRead: "#66d9ef",
  regPc: "#66d9ef",

  asmMnemonic: "#f92672",
  asmRegister: "#66d9ef",
  asmMemory: "#e6db74",
  asmImmediate: "#fd971f",
  asmShift: "#a6e22e",

  borderColor: "#49483e",

  scrollbarThumb: "#49483e",
  scrollbarThumbHover: "#5e5d50",

  arrowAnchor: "#f92672",
  arrowDef: "#a6e22e",
  arrowUse: "#66d9ef",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(166,226,46,0.12)",
  arrowUseBg: "rgba(102,217,239,0.12)",
  strikethroughLine: "#888888",
  commentGutter: "rgba(253,151,31,0.8)",
  commentInline: "#75715e",
  callInfoNormal: "#f92672",
  callInfoJni: "#ae81ff",

  minimapSelected: "rgba(73, 72, 62, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Dracula — 紫色调经典深色
   ═══════════════════════════════════════════════════════════ */
const dracula: ThemeColors = {
  bgPrimary: "#282a36",
  bgSecondary: "#2d2f3d",
  bgRowEven: "#282a36",
  bgRowOdd: "#2c2e3a",
  bgFuncEntry: "#283040",
  bgSelected: "#44475a",
  bgTainted: "#3d2842",
  bgInput: "#343746",
  bgDialog: "#21222c",

  textPrimary: "#f8f8f2",
  textSecondary: "#6272a4",
  textAddress: "#8be9fd",
  textChanges: "#f1fa8c",
  textAsciiPrintable: "#50fa7b",
  textAsciiNonprint: "#44475a",
  textHexZero: "#44475a",
  textHexHighlight: "#f1fa8c",

  btnPrimary: "#bd93f9",
  btnTaint: "#ffb86c",

  regChanged: "#ff5555",
  regRead: "#8be9fd",
  regPc: "#8be9fd",

  asmMnemonic: "#ff79c6",
  asmRegister: "#8be9fd",
  asmMemory: "#f1fa8c",
  asmImmediate: "#ffb86c",
  asmShift: "#50fa7b",

  borderColor: "#44475a",

  scrollbarThumb: "#44475a",
  scrollbarThumbHover: "#565972",

  arrowAnchor: "#ff5555",
  arrowDef: "#50fa7b",
  arrowUse: "#8be9fd",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(80,250,123,0.12)",
  arrowUseBg: "rgba(139,233,253,0.12)",
  strikethroughLine: "#888888",
  commentGutter: "rgba(255,184,108,0.8)",
  commentInline: "#6272a4",
  callInfoNormal: "#ff5555",
  callInfoJni: "#ff79c6",

  minimapSelected: "rgba(68, 71, 90, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Nord — 北欧冷色调
   ═══════════════════════════════════════════════════════════ */
const nord: ThemeColors = {
  bgPrimary: "#2e3440",
  bgSecondary: "#3b4252",
  bgRowEven: "#2e3440",
  bgRowOdd: "#313845",
  bgFuncEntry: "#2e3a4a",
  bgSelected: "#434c5e",
  bgTainted: "#3e2e40",
  bgInput: "#3b4252",
  bgDialog: "#272d38",

  textPrimary: "#d8dee9",
  textSecondary: "#616e88",
  textAddress: "#88c0d0",
  textChanges: "#ebcb8b",
  textAsciiPrintable: "#a3be8c",
  textAsciiNonprint: "#434c5e",
  textHexZero: "#434c5e",
  textHexHighlight: "#ebcb8b",

  btnPrimary: "#5e81ac",
  btnTaint: "#d08770",

  regChanged: "#bf616a",
  regRead: "#88c0d0",
  regPc: "#88c0d0",

  asmMnemonic: "#b48ead",
  asmRegister: "#88c0d0",
  asmMemory: "#ebcb8b",
  asmImmediate: "#d08770",
  asmShift: "#a3be8c",

  borderColor: "#434c5e",

  scrollbarThumb: "#434c5e",
  scrollbarThumbHover: "#4c566a",

  arrowAnchor: "#bf616a",
  arrowDef: "#a3be8c",
  arrowUse: "#88c0d0",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(163,190,140,0.12)",
  arrowUseBg: "rgba(136,192,208,0.12)",
  strikethroughLine: "#7b88a1",
  commentGutter: "rgba(208,135,112,0.8)",
  commentInline: "#616e88",
  callInfoNormal: "#bf616a",
  callInfoJni: "#b48ead",

  minimapSelected: "rgba(67, 76, 94, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Catppuccin Mocha — 柔和暖色调深色
   ═══════════════════════════════════════════════════════════ */
const catppuccinMocha: ThemeColors = {
  bgPrimary: "#1e1e2e",
  bgSecondary: "#25253a",
  bgRowEven: "#1e1e2e",
  bgRowOdd: "#222234",
  bgFuncEntry: "#1e2a3e",
  bgSelected: "#45475a",
  bgTainted: "#3e1e38",
  bgInput: "#313244",
  bgDialog: "#181825",

  textPrimary: "#cdd6f4",
  textSecondary: "#6c7086",
  textAddress: "#89b4fa",
  textChanges: "#f9e2af",
  textAsciiPrintable: "#a6e3a1",
  textAsciiNonprint: "#45475a",
  textHexZero: "#45475a",
  textHexHighlight: "#f9e2af",

  btnPrimary: "#89b4fa",
  btnTaint: "#fab387",

  regChanged: "#f38ba8",
  regRead: "#89b4fa",
  regPc: "#89b4fa",

  asmMnemonic: "#cba6f7",
  asmRegister: "#89dceb",
  asmMemory: "#f9e2af",
  asmImmediate: "#fab387",
  asmShift: "#a6e3a1",

  borderColor: "#45475a",

  scrollbarThumb: "#45475a",
  scrollbarThumbHover: "#585b70",

  arrowAnchor: "#f38ba8",
  arrowDef: "#a6e3a1",
  arrowUse: "#89b4fa",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(166,227,161,0.12)",
  arrowUseBg: "rgba(137,180,250,0.12)",
  strikethroughLine: "#7f849c",
  commentGutter: "rgba(250,179,135,0.8)",
  commentInline: "#6c7086",
  callInfoNormal: "#f38ba8",
  callInfoJni: "#cba6f7",

  minimapSelected: "rgba(69, 71, 90, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Catppuccin Latte — Catppuccin 浅色版
   ═══════════════════════════════════════════════════════════ */
const catppuccinLatte: ThemeColors = {
  bgPrimary: "#eff1f5",
  bgSecondary: "#e6e9ef",
  bgRowEven: "#eff1f5",
  bgRowOdd: "#e9ecf2",
  bgFuncEntry: "#dce5f5",
  bgSelected: "#bcc0cc",
  bgTainted: "#f2dce8",
  bgInput: "#ccd0da",
  bgDialog: "#e6e9ef",

  textPrimary: "#4c4f69",
  textSecondary: "#8c8fa1",
  textAddress: "#1e66f5",
  textChanges: "#df8e1d",
  textAsciiPrintable: "#40a02b",
  textAsciiNonprint: "#bcc0cc",
  textHexZero: "#bcc0cc",
  textHexHighlight: "#df8e1d",

  btnPrimary: "#1e66f5",
  btnTaint: "#fe640b",

  regChanged: "#d20f39",
  regRead: "#1e66f5",
  regPc: "#1e66f5",

  asmMnemonic: "#8839ef",
  asmRegister: "#04a5e5",
  asmMemory: "#df8e1d",
  asmImmediate: "#fe640b",
  asmShift: "#40a02b",

  borderColor: "#bcc0cc",

  scrollbarThumb: "#bcc0cc",
  scrollbarThumbHover: "#9ca0b0",

  arrowAnchor: "#d20f39",
  arrowDef: "#40a02b",
  arrowUse: "#1e66f5",
  ...LIGHT_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(64,160,43,0.10)",
  arrowUseBg: "rgba(30,102,245,0.10)",
  strikethroughLine: "#9ca0b0",
  commentGutter: "rgba(254,100,11,0.7)",
  commentInline: "#8c8fa1",
  callInfoNormal: "#d20f39",
  callInfoJni: "#8839ef",

  minimapSelected: "rgba(188, 192, 204, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Gruvbox Dark — 复古暖色调
   ═══════════════════════════════════════════════════════════ */
const gruvboxDark: ThemeColors = {
  bgPrimary: "#282828",
  bgSecondary: "#32302f",
  bgRowEven: "#282828",
  bgRowOdd: "#2c2b2a",
  bgFuncEntry: "#2e3528",
  bgSelected: "#504945",
  bgTainted: "#402828",
  bgInput: "#3c3836",
  bgDialog: "#1d2021",

  textPrimary: "#ebdbb2",
  textSecondary: "#928374",
  textAddress: "#83a598",
  textChanges: "#fabd2f",
  textAsciiPrintable: "#b8bb26",
  textAsciiNonprint: "#504945",
  textHexZero: "#504945",
  textHexHighlight: "#fabd2f",

  btnPrimary: "#458588",
  btnTaint: "#d65d0e",

  regChanged: "#fb4934",
  regRead: "#83a598",
  regPc: "#83a598",

  asmMnemonic: "#d3869b",
  asmRegister: "#83a598",
  asmMemory: "#fabd2f",
  asmImmediate: "#fe8019",
  asmShift: "#b8bb26",

  borderColor: "#504945",

  scrollbarThumb: "#504945",
  scrollbarThumbHover: "#665c54",

  arrowAnchor: "#fb4934",
  arrowDef: "#b8bb26",
  arrowUse: "#83a598",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(184,187,38,0.12)",
  arrowUseBg: "rgba(131,165,152,0.12)",
  strikethroughLine: "#928374",
  commentGutter: "rgba(254,128,25,0.8)",
  commentInline: "#928374",
  callInfoNormal: "#fb4934",
  callInfoJni: "#d3869b",

  minimapSelected: "rgba(80, 73, 69, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Tokyo Night — 蓝紫色调，灵感来自东京夜景
   ═══════════════════════════════════════════════════════════ */
const tokyoNight: ThemeColors = {
  bgPrimary: "#1a1b26",
  bgSecondary: "#1f2030",
  bgRowEven: "#1a1b26",
  bgRowOdd: "#1e1f2b",
  bgFuncEntry: "#1a2536",
  bgSelected: "#33467c",
  bgTainted: "#36213e",
  bgInput: "#292e42",
  bgDialog: "#16161e",

  textPrimary: "#a9b1d6",
  textSecondary: "#565f89",
  textAddress: "#7aa2f7",
  textChanges: "#e0af68",
  textAsciiPrintable: "#9ece6a",
  textAsciiNonprint: "#3b4261",
  textHexZero: "#3b4261",
  textHexHighlight: "#e0af68",

  btnPrimary: "#7aa2f7",
  btnTaint: "#ff9e64",

  regChanged: "#f7768e",
  regRead: "#7aa2f7",
  regPc: "#7aa2f7",

  asmMnemonic: "#bb9af7",
  asmRegister: "#7dcfff",
  asmMemory: "#e0af68",
  asmImmediate: "#ff9e64",
  asmShift: "#9ece6a",

  borderColor: "#3b4261",

  scrollbarThumb: "#3b4261",
  scrollbarThumbHover: "#4e5579",

  arrowAnchor: "#f7768e",
  arrowDef: "#9ece6a",
  arrowUse: "#7aa2f7",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(158,206,106,0.12)",
  arrowUseBg: "rgba(122,162,247,0.12)",
  strikethroughLine: "#7a7e8e",
  commentGutter: "rgba(255,158,100,0.8)",
  commentInline: "#565f89",
  callInfoNormal: "#f7768e",
  callInfoJni: "#bb9af7",

  minimapSelected: "rgba(51, 70, 124, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Solarized Dark — Ethan Schoonover 经典
   ═══════════════════════════════════════════════════════════ */
const solarizedDark: ThemeColors = {
  bgPrimary: "#002b36",
  bgSecondary: "#073642",
  bgRowEven: "#002b36",
  bgRowOdd: "#013440",
  bgFuncEntry: "#003848",
  bgSelected: "#1a4a5a",
  bgTainted: "#2a2030",
  bgInput: "#073642",
  bgDialog: "#00212b",

  textPrimary: "#839496",
  textSecondary: "#586e75",
  textAddress: "#268bd2",
  textChanges: "#b58900",
  textAsciiPrintable: "#859900",
  textAsciiNonprint: "#073642",
  textHexZero: "#073642",
  textHexHighlight: "#b58900",

  btnPrimary: "#268bd2",
  btnTaint: "#cb4b16",

  regChanged: "#dc322f",
  regRead: "#268bd2",
  regPc: "#268bd2",

  asmMnemonic: "#d33682",
  asmRegister: "#2aa198",
  asmMemory: "#b58900",
  asmImmediate: "#cb4b16",
  asmShift: "#859900",

  borderColor: "#073642",

  scrollbarThumb: "#0a4a5a",
  scrollbarThumbHover: "#1a5a6a",

  arrowAnchor: "#dc322f",
  arrowDef: "#859900",
  arrowUse: "#268bd2",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(133,153,0,0.12)",
  arrowUseBg: "rgba(38,139,210,0.12)",
  strikethroughLine: "#586e75",
  commentGutter: "rgba(203,75,22,0.8)",
  commentInline: "#586e75",
  callInfoNormal: "#dc322f",
  callInfoJni: "#d33682",

  minimapSelected: "rgba(26, 74, 90, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   Solarized Light
   ═══════════════════════════════════════════════════════════ */
const solarizedLight: ThemeColors = {
  bgPrimary: "#fdf6e3",
  bgSecondary: "#eee8d5",
  bgRowEven: "#fdf6e3",
  bgRowOdd: "#f5efdc",
  bgFuncEntry: "#e8e0ce",
  bgSelected: "#d6ccb8",
  bgTainted: "#f5dce8",
  bgInput: "#eee8d5",
  bgDialog: "#f5efdc",

  textPrimary: "#657b83",
  textSecondary: "#93a1a1",
  textAddress: "#268bd2",
  textChanges: "#b58900",
  textAsciiPrintable: "#859900",
  textAsciiNonprint: "#eee8d5",
  textHexZero: "#eee8d5",
  textHexHighlight: "#b58900",

  btnPrimary: "#268bd2",
  btnTaint: "#cb4b16",

  regChanged: "#dc322f",
  regRead: "#268bd2",
  regPc: "#268bd2",

  asmMnemonic: "#d33682",
  asmRegister: "#2aa198",
  asmMemory: "#b58900",
  asmImmediate: "#cb4b16",
  asmShift: "#859900",

  borderColor: "#d6ccb8",

  scrollbarThumb: "#d0c8b0",
  scrollbarThumbHover: "#bab2a0",

  arrowAnchor: "#dc322f",
  arrowDef: "#859900",
  arrowUse: "#268bd2",
  ...LIGHT_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(133,153,0,0.10)",
  arrowUseBg: "rgba(38,139,210,0.10)",
  strikethroughLine: "#93a1a1",
  commentGutter: "rgba(203,75,22,0.7)",
  commentInline: "#93a1a1",
  callInfoNormal: "#dc322f",
  callInfoJni: "#d33682",

  minimapSelected: "rgba(214, 204, 184, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   GitHub Light
   ═══════════════════════════════════════════════════════════ */
const githubLight: ThemeColors = {
  bgPrimary: "#ffffff",
  bgSecondary: "#f6f8fa",
  bgRowEven: "#ffffff",
  bgRowOdd: "#f6f8fa",
  bgFuncEntry: "#ddf4ff",
  bgSelected: "#b6e3ff",
  bgTainted: "#ffebe9",
  bgInput: "#f6f8fa",
  bgDialog: "#f0f2f5",

  textPrimary: "#1f2328",
  textSecondary: "#656d76",
  textAddress: "#0550ae",
  textChanges: "#953800",
  textAsciiPrintable: "#116329",
  textAsciiNonprint: "#d0d7de",
  textHexZero: "#d0d7de",
  textHexHighlight: "#953800",

  btnPrimary: "#0969da",
  btnTaint: "#bc4c00",

  regChanged: "#cf222e",
  regRead: "#0550ae",
  regPc: "#0550ae",

  asmMnemonic: "#8250df",
  asmRegister: "#0550ae",
  asmMemory: "#953800",
  asmImmediate: "#bc4c00",
  asmShift: "#116329",

  borderColor: "#d0d7de",

  scrollbarThumb: "#c8ccd0",
  scrollbarThumbHover: "#afb8c1",

  arrowAnchor: "#cf222e",
  arrowDef: "#116329",
  arrowUse: "#0550ae",
  ...LIGHT_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(17,99,41,0.10)",
  arrowUseBg: "rgba(5,80,174,0.10)",
  strikethroughLine: "#afb8c1",
  commentGutter: "rgba(188,76,0,0.7)",
  commentInline: "#656d76",
  callInfoNormal: "#cf222e",
  callInfoJni: "#8250df",

  minimapSelected: "rgba(182, 227, 255, 0.6)",
};

/* ═══════════════════════════════════════════════════════════
   High Contrast — 高对比度（辅助视觉障碍）
   ═══════════════════════════════════════════════════════════ */
const highContrast: ThemeColors = {
  bgPrimary: "#000000",
  bgSecondary: "#0a0a0a",
  bgRowEven: "#000000",
  bgRowOdd: "#0a0a0a",
  bgFuncEntry: "#001830",
  bgSelected: "#003060",
  bgTainted: "#400020",
  bgInput: "#1a1a1a",
  bgDialog: "#0a0a0a",

  textPrimary: "#ffffff",
  textSecondary: "#b0b0b0",
  textAddress: "#6cb6ff",
  textChanges: "#ffdf5d",
  textAsciiPrintable: "#7ee787",
  textAsciiNonprint: "#333333",
  textHexZero: "#333333",
  textHexHighlight: "#ffdf5d",

  btnPrimary: "#409eff",
  btnTaint: "#f0883e",

  regChanged: "#ff6b6b",
  regRead: "#6cb6ff",
  regPc: "#6cb6ff",

  asmMnemonic: "#e2b5ff",
  asmRegister: "#56d4dd",
  asmMemory: "#ffdf5d",
  asmImmediate: "#ffa657",
  asmShift: "#7ee787",

  borderColor: "#454545",

  scrollbarThumb: "#454545",
  scrollbarThumbHover: "#666666",

  arrowAnchor: "#ff6b6b",
  arrowDef: "#7ee787",
  arrowUse: "#6cb6ff",
  ...DARK_CANVAS_DEFAULTS,
  arrowDefBg: "rgba(126,231,135,0.15)",
  arrowUseBg: "rgba(108,182,255,0.15)",
  bgHover: "rgba(255,255,255,0.06)",
  arrowAnchorBg: "rgba(255,255,255,0.10)",
  bgMultiSelect: "rgba(80,200,120,0.22)",
  strikethroughLine: "#aaaaaa",
  commentGutter: "rgba(240,136,62,0.9)",
  commentInline: "#b0b0b0",
  callInfoNormal: "#ff6b6b",
  callInfoJni: "#e2b5ff",

  minimapSelected: "rgba(0, 48, 96, 0.7)",
  minimapViewportBg: "rgba(255,255,255,0.10)",
  minimapViewportHover: "rgba(255,255,255,0.20)",
  minimapViewportDrag: "rgba(255,255,255,0.28)",
  minimapViewportBorder: "rgba(255,255,255,0.35)",
};

/* ═══════════════════════════════════════════════════════════ */

export const THEMES: ThemeMeta[] = [
  // Dark themes
  { id: "dark",             label: "Dark",             group: "dark",  colors: dark },
  { id: "dim",              label: "Dim",              group: "dark",  colors: dim },
  { id: "monokai",          label: "Monokai",          group: "dark",  colors: monokai },
  { id: "dracula",          label: "Dracula",          group: "dark",  colors: dracula },
  { id: "nord",             label: "Nord",             group: "dark",  colors: nord },
  { id: "catppuccin-mocha", label: "Catppuccin Mocha", group: "dark",  colors: catppuccinMocha },
  { id: "gruvbox-dark",     label: "Gruvbox Dark",     group: "dark",  colors: gruvboxDark },
  { id: "tokyo-night",      label: "Tokyo Night",      group: "dark",  colors: tokyoNight },
  { id: "solarized-dark",   label: "Solarized Dark",   group: "dark",  colors: solarizedDark },
  { id: "high-contrast",    label: "High Contrast",    group: "dark",  colors: highContrast },
  // Light themes
  { id: "light",            label: "Light",            group: "light", colors: light },
  { id: "catppuccin-latte", label: "Catppuccin Latte", group: "light", colors: catppuccinLatte },
  { id: "solarized-light",  label: "Solarized Light",  group: "light", colors: solarizedLight },
  { id: "github-light",     label: "GitHub Light",     group: "light", colors: githubLight },
];

export function getTheme(id: ThemeId): ThemeColors {
  return THEMES.find(t => t.id === id)?.colors ?? dark;
}
