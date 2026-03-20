import { altKey } from "./platform";

export const HIGHLIGHT_COLORS: { key: string; label: string; color: string; shortcut: () => string }[] = [
  { key: "red", label: "Red", color: "rgba(220,60,60,0.20)", shortcut: () => altKey("1") },
  { key: "yellow", label: "Yellow", color: "rgba(220,200,50,0.20)", shortcut: () => altKey("2") },
  { key: "green", label: "Green", color: "rgba(80,200,120,0.20)", shortcut: () => altKey("3") },
  { key: "blue", label: "Blue", color: "rgba(60,120,220,0.20)", shortcut: () => altKey("4") },
  { key: "cyan", label: "Cyan", color: "rgba(60,200,200,0.20)", shortcut: () => altKey("5") },
];
