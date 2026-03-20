// ARM64 汇编 token 正则表达式（共用）
// 三处使用: DisasmHighlight.tsx, TraceTable.tsx, Minimap.tsx

/** ARM64 寄存器名（锚定匹配） */
export const REG_RE = /^(?:x\d{1,2}|w\d{1,2}|sp|lr|pc|xzr|wzr|q\d{1,2}|v\d{1,2}|d\d{1,2}|s\d{1,2}|h\d{1,2}|b\d{1,2}|nzcv)$/i;

/** 移位/扩展操作符（锚定匹配） */
export const SHIFT_RE = /^(?:lsl|lsr|asr|ror|sxtw|sxth|sxtb|uxtw|uxth|uxtb|sxtx|uxtx)$/i;

/** 立即数前缀 */
export const IMM_RE = /^#/;

/** 方括号及可选 ! 后缀 */
export const BRACKET_RE = /^[\[\]]!?$/;

/** 汇编行分词正则（全局匹配，使用 exec 前需重置 lastIndex） */
export const TOKEN_RE = /(\[|\]!?|#-?0x[0-9a-f]+|#-?\d+|[a-z]\w*(?:\.\w+)?|\S)/gi;
