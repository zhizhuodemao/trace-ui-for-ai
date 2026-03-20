// macOS 平台检测
export const isMac = /Mac|iPhone|iPad|iPod/.test(navigator.platform);

// 修饰键显示文本：macOS 用 ⌘，其他用 Ctrl
export function modKey(key: string): string {
  return isMac ? `⌘+${key}` : `Ctrl+${key}`;
}

// Alt 键显示文本：macOS 用 ⌥，其他用 Alt
export function altKey(key: string): string {
  return isMac ? `⌥+${key}` : `Alt+${key}`;
}

// 检查事件中修饰键是否按下：macOS 检查 metaKey，其他检查 ctrlKey
export function isModKey(e: KeyboardEvent | React.KeyboardEvent): boolean {
  return isMac ? e.metaKey : e.ctrlKey;
}
