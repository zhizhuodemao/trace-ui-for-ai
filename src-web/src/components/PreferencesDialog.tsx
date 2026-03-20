import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Preferences } from "../hooks/usePreferences";
import { THEMES } from "../theme/themes";
import type { ThemeId } from "../theme/themes";
import { themeStore } from "../stores/themeStore";

interface Props {
  preferences: Preferences;
  onSave: (prefs: Preferences) => void;
  onClose: () => void;
  onClearCache?: () => void;
}

interface CacheInfo {
  path: string;
  size: number;
}

const TABS = ["General", "Analysis", "Cache"] as const;
type Tab = typeof TABS[number];

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const DIALOG_WIDTH = 620;
const DIALOG_HEIGHT = 480;

export default function PreferencesDialog({ preferences, onSave, onClose, onClearCache }: Props) {
  const [local, setLocal] = useState(preferences);
  const [tab, setTab] = useState<Tab>("General");
  const [cacheInfo, setCacheInfo] = useState<CacheInfo | null>(null);
  const [clearing, setClearing] = useState(false);
  const [originalTheme] = useState<ThemeId>(preferences.theme);

  const handleClose = useCallback(() => {
    // 取消时恢复原主题
    themeStore.set(originalTheme);
    onClose();
  }, [originalTheme, onClose]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") handleClose(); };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [handleClose]);

  const refreshCacheInfo = useCallback(() => {
    invoke<CacheInfo>("get_cache_dir").then(setCacheInfo).catch(console.error);
  }, []);

  useEffect(() => { refreshCacheInfo(); }, [refreshCacheInfo]);

  const handleBrowse = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({ directory: true, title: "Select Cache Directory" });
    if (selected) {
      setLocal(prev => ({ ...prev, cacheDir: selected as string }));
    }
  }, []);

  const handleClear = useCallback(async () => {
    setClearing(true);
    try {
      await invoke("clear_all_cache");
      refreshCacheInfo();
      onClearCache?.();
    } catch (e) {
      console.error("clear cache failed:", e);
    } finally {
      setClearing(false);
    }
  }, [refreshCacheInfo, onClearCache]);

  const handleSave = useCallback(() => {
    const dir = local.cacheDir.trim() || null;
    invoke("set_cache_dir", { path: dir }).catch(console.error);
    onSave(local);
    onClose();
  }, [local, onSave, onClose]);

  return (
    <div
      style={{
        position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex", alignItems: "center", justifyContent: "center",
        zIndex: 10000,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) handleClose(); }}
    >
      <div
        style={{
          background: "var(--bg-dialog)",
          border: "1px solid var(--border-color)",
          borderRadius: 8,
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
          width: Math.min(DIALOG_WIDTH, window.innerWidth - 40),
          height: Math.min(DIALOG_HEIGHT, window.innerHeight - 80),
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Header ── */}
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "14px 20px",
          borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
        }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>
            Preferences
          </div>
          <button
            onClick={handleClose}
            style={{
              background: "transparent", border: "none",
              color: "var(--text-secondary)", fontSize: 16,
              cursor: "pointer", padding: "0 2px", lineHeight: 1,
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--text-primary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-secondary)"; }}
          >
            ×
          </button>
        </div>

        {/* ── Body ── */}
        <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>

          {/* Sidebar */}
          <div style={{
            width: 120, flexShrink: 0,
            borderRight: "1px solid var(--border-color)",
            padding: "8px 6px",
            display: "flex", flexDirection: "column", gap: 1,
          }}>
            {TABS.map(t => {
              const active = tab === t;
              return (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "var(--bg-input)"; }}
                  onMouseLeave={(e) => { if (!active) e.currentTarget.style.background = "transparent"; }}
                  style={{
                    padding: "6px 10px",
                    fontSize: 12,
                    color: active ? "var(--text-primary)" : "var(--text-secondary)",
                    background: active ? "var(--bg-selected)" : "transparent",
                    border: "none",
                    borderRadius: 4,
                    cursor: "pointer",
                    textAlign: "left" as const,
                    width: "100%",
                  }}
                >
                  {t}
                </button>
              );
            })}
          </div>

          {/* Content — scrollable */}
          <div style={{ flex: 1, padding: "16px 20px", overflowY: "auto" }}>

            {/* ── General Tab ── */}
            {tab === "General" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
                {/* Theme */}
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)", fontWeight: 600 }}>
                    Theme
                  </div>
                  {(["dark", "light"] as const).map(group => {
                    const groupThemes = THEMES.filter(t => t.group === group);
                    return (
                      <div key={group} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                        <div style={{ fontSize: 10, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: 0.5 }}>
                          {group === "dark" ? "Dark" : "Light"}
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                          {groupThemes.map(t => {
                            const active = local.theme === t.id;
                            return (
                              <button
                                key={t.id}
                                onClick={() => {
                                  setLocal(prev => ({ ...prev, theme: t.id }));
                                  themeStore.set(t.id); // 即时预览
                                }}
                                onMouseEnter={(e) => { if (!active) e.currentTarget.style.borderColor = "var(--text-secondary)"; }}
                                onMouseLeave={(e) => { if (!active) e.currentTarget.style.borderColor = "var(--border-color)"; }}
                                style={{
                                  padding: "4px 10px",
                                  fontSize: 11,
                                  color: active ? "#fff" : "var(--text-primary)",
                                  background: active ? "var(--btn-primary)" : "var(--bg-input)",
                                  border: `1px solid ${active ? "var(--btn-primary)" : "var(--border-color)"}`,
                                  borderRadius: 4,
                                  cursor: "pointer",
                                  fontWeight: active ? 600 : 400,
                                  transition: "all 0.15s",
                                }}
                              >
                                {t.label}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Startup */}
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)", fontWeight: 600 }}>
                    Startup
                  </div>
                  <label style={{
                    display: "flex", alignItems: "center", gap: 8,
                    fontSize: 12, color: "var(--text-primary)", cursor: "pointer",
                  }}>
                    <input
                      type="checkbox"
                      checked={local.reopenLastFile}
                      onChange={(e) => setLocal(prev => ({ ...prev, reopenLastFile: e.target.checked }))}
                      style={{ accentColor: "var(--btn-primary)" }}
                    />
                    Restore previous session on startup
                  </label>
                </div>
              </div>
            )}

            {/* ── Analysis Tab ── */}
            {tab === "Analysis" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                <div style={{ fontSize: 11, color: "var(--text-secondary)", fontWeight: 600 }}>
                  Strings
                </div>
                <label style={{
                  display: "flex", alignItems: "center", gap: 8,
                  fontSize: 12, color: "var(--text-primary)", cursor: "pointer",
                }}>
                  <input
                    type="checkbox"
                    checked={local.scanStringsOnBuild}
                    onChange={(e) => setLocal(prev => ({ ...prev, scanStringsOnBuild: e.target.checked }))}
                    style={{ accentColor: "var(--btn-primary)" }}
                  />
                  Scan strings during index build
                </label>
                <div style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.4, marginTop: -6 }}>
                  When disabled, strings are not extracted during startup indexing. You can manually scan from Analysis → Scan Strings.
                </div>

                <div style={{ fontSize: 11, color: "var(--text-secondary)", fontWeight: 600, marginTop: 8 }}>
                  Taint Analysis
                </div>
                <label style={{
                  display: "flex", alignItems: "center", gap: 8,
                  fontSize: 12, color: "var(--text-primary)", cursor: "pointer",
                }}>
                  <input
                    type="checkbox"
                    checked={local.confirmTaintRestore}
                    onChange={(e) => setLocal(prev => ({ ...prev, confirmTaintRestore: e.target.checked }))}
                    style={{ accentColor: "var(--btn-primary)" }}
                  />
                  Confirm before restoring taint analysis state
                </label>
                <div style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.4, marginTop: -6 }}>
                  When enabled, a confirmation dialog will be shown before restoring the previous taint analysis state on file reopen. Useful for large traces where re-analysis may take a long time.
                </div>
              </div>
            )}

            {/* ── Cache Tab ── */}
            {tab === "Cache" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>

                {/* Cache Directory */}
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)", fontWeight: 600 }}>
                    Cache Directory
                  </div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input
                      type="text"
                      value={local.cacheDir}
                      onChange={(e) => setLocal(prev => ({ ...prev, cacheDir: e.target.value }))}
                      placeholder={cacheInfo?.path ?? "Default"}
                      style={{
                        flex: 1, padding: "5px 8px", fontSize: 11,
                        background: "var(--bg-input)", border: "1px solid var(--border-color)",
                        borderRadius: 4, color: "var(--text-primary)",
                        fontFamily: "var(--font-mono)", outline: "none",
                      }}
                    />
                    <button
                      onClick={handleBrowse}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-selected)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-input)"; }}
                      style={{
                        padding: "5px 10px", fontSize: 11,
                        background: "var(--bg-input)", border: "1px solid var(--border-color)",
                        borderRadius: 4, color: "var(--text-primary)", cursor: "pointer",
                        whiteSpace: "nowrap" as const,
                      }}
                    >
                      Browse...
                    </button>
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.4 }}>
                    Leave empty to use default path. Changes take effect on next index build.
                  </div>
                </div>

                {/* Cache Usage */}
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)", fontWeight: 600 }}>
                    Cache Usage
                  </div>
                  <div style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    background: "var(--bg-input)", border: "1px solid var(--border-color)",
                    borderRadius: 4, padding: "8px 12px",
                  }}>
                    <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
                      {cacheInfo ? formatSize(cacheInfo.size) : "..."}
                    </span>
                    <button
                      onClick={handleClear}
                      disabled={clearing}
                      onMouseEnter={(e) => { if (!clearing) e.currentTarget.style.opacity = "0.85"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.opacity = clearing ? "0.6" : "1"; }}
                      style={{
                        padding: "4px 12px", fontSize: 11,
                        background: "var(--reg-changed)", border: "none",
                        borderRadius: 4, color: "#fff",
                        cursor: clearing ? "default" : "pointer",
                        opacity: clearing ? 0.6 : 1,
                      }}
                    >
                      {clearing ? "Clearing..." : "Clear Cache"}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Footer ── */}
        <div style={{
          display: "flex", justifyContent: "flex-end", gap: 8,
          padding: "10px 20px",
          borderTop: "1px solid var(--border-color)",
          flexShrink: 0,
        }}>
          <button
            onClick={handleClose}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-secondary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-input)"; }}
            style={{
              padding: "5px 16px",
              background: "var(--bg-input)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 4, cursor: "pointer", fontSize: 12,
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            onMouseEnter={(e) => { e.currentTarget.style.opacity = "0.85"; }}
            onMouseLeave={(e) => { e.currentTarget.style.opacity = "1"; }}
            style={{
              padding: "5px 16px",
              background: "var(--btn-primary)",
              color: "#fff",
              border: "none",
              borderRadius: 4, cursor: "pointer", fontSize: 12, fontWeight: 600,
            }}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
