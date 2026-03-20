import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useFloatingWindowInit } from "../hooks/useFloatingWindowInit";
import type { DependencyGraph } from "../types/trace";
import ExpressionTreeView from "./dep-tree/ExpressionTreeView";
import DagGraphView from "./dep-tree/DagGraphView";

/** 父窗口通过 event 传递的轻量参数 */
interface DepTreeParams {
  sessionId: string;
  seq?: number;
  target?: string;
  dataOnly?: boolean;
  fromSlice?: boolean;
}

const NODE_LIMITS = [1000, 5000, 10000, 50000];
const DEFAULT_LIMIT = 10000;

type TabKey = "tree" | "dag";

export default function DependencyTreePanel() {
  const params = useFloatingWindowInit<DepTreeParams>("dep-tree");
  const [graph, setGraph] = useState<DependencyGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("tree");
  const [maxNodes, setMaxNodes] = useState(DEFAULT_LIMIT);
  const [dataOnly, setDataOnly] = useState(false);
  const [exprMode, setExprMode] = useState<"c" | "asm">("c");

  // Esc to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        getCurrentWindow().close();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // 从后端获取数据
  const fetchGraph = useCallback(async (p: DepTreeParams, limit: number, dataOnlyVal: boolean) => {
    setLoading(true);
    setError(null);
    try {
      let result: DependencyGraph;
      if (p.fromSlice) {
        result = await invoke<DependencyGraph>("build_dependency_tree_from_slice", {
          sessionId: p.sessionId,
          maxNodes: limit,
          dataOnly: dataOnlyVal,
        });
      } else {
        result = await invoke<DependencyGraph>("build_dependency_tree", {
          sessionId: p.sessionId,
          seq: p.seq,
          target: p.target,
          dataOnly: dataOnlyVal,
          maxNodes: limit,
        });
      }
      setGraph(result);
      setLoading(false);
    } catch (e) {
      setError(String(e));
      setLoading(false);
    }
  }, []);

  // 收到参数后首次加载
  useEffect(() => {
    if (!params) return;
    setDataOnly(params.dataOnly ?? false);
    fetchGraph(params, maxNodes, params.dataOnly ?? false);
  }, [params]);

  // 参数调整时重新加载
  const handleLimitChange = useCallback((newLimit: number) => {
    setMaxNodes(newLimit);
    if (params) fetchGraph(params, newLimit, dataOnly);
  }, [params, dataOnly, fetchGraph]);

  const handleDataOnlyChange = useCallback((val: boolean) => {
    setDataOnly(val);
    if (params) fetchGraph(params, maxNodes, val);
  }, [params, maxNodes, fetchGraph]);

  // 等待参数
  if (!params) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Initializing...</span>
      </div>
    );
  }

  // 加载中
  if (loading) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Building dependency tree...</span>
      </div>
    );
  }

  // 错误
  if (error) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
        <span style={{ color: "#e06c75", fontSize: 12 }}>{error}</span>
      </div>
    );
  }

  if (!graph) return null;

  const tabs: { key: TabKey; label: string }[] = [
    { key: "tree", label: "Expression Tree" },
    { key: "dag", label: "DAG" },
  ];

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Tab bar */}
      <div style={{
        display: "flex",
        alignItems: "center",
        borderBottom: "1px solid var(--border-color)",
        flexShrink: 0,
        background: "var(--bg-secondary)",
        padding: "0 8px",
        gap: 0,
      }}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              padding: "6px 14px",
              fontSize: 12,
              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
              background: "transparent",
              border: "none",
              borderBottom: activeTab === tab.key ? "2px solid #61afef" : "2px solid transparent",
              color: activeTab === tab.key ? "var(--text-primary, #abb2bf)" : "var(--text-secondary, #5c6370)",
              cursor: "pointer",
            }}
          >
            {tab.label}
          </button>
        ))}
        <button
          onClick={() => setExprMode(exprMode === "c" ? "asm" : "c")}
          style={{
            padding: "3px 8px",
            fontSize: 10,
            fontFamily: '"JetBrains Mono", "Fira Code", monospace',
            background: "var(--bg-tertiary, #2c313a)",
            border: "1px solid var(--border-color)",
            borderRadius: 3,
            color: "var(--text-primary, #abb2bf)",
            cursor: "pointer",
            marginLeft: 8,
          }}
          title={exprMode === "c" ? "Switch to Assembly" : "Switch to C Pseudocode"}
        >
          {exprMode === "c" ? "C" : "ASM"}
        </button>
        <span style={{
          marginLeft: "auto",
          fontSize: 10,
          color: "var(--text-secondary, #5c6370)",
          padding: "0 8px",
        }}>
          {graph.nodes.length.toLocaleString()} nodes / {graph.edges.length.toLocaleString()} edges
        </span>
      </div>

      {/* 截断控制栏（仅当截断时显示） */}
      {graph.truncated && (
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "6px 12px",
          fontSize: 11,
          background: "rgba(224, 108, 117, 0.08)",
          borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
          flexWrap: "wrap",
        }}>
          <span style={{ color: "#e5c07b" }}>
            ⚠ Showing {graph.nodes.length.toLocaleString()} / {graph.totalReachable.toLocaleString()} nodes
          </span>

          <label style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--text-secondary)" }}>
            Max nodes
            <select
              value={maxNodes}
              onChange={(e) => handleLimitChange(Number(e.target.value))}
              style={{
                background: "var(--bg-secondary)",
                color: "var(--text-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 3,
                padding: "1px 4px",
                fontSize: 11,
              }}
            >
              {NODE_LIMITS.map((v) => (
                <option key={v} value={v}>{v.toLocaleString()}</option>
              ))}
            </select>
          </label>

          <label style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--text-secondary)", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={dataOnly}
              onChange={(e) => handleDataOnlyChange(e.target.checked)}
              style={{ margin: 0 }}
            />
            Data only
          </label>
        </div>
      )}

      {/* Content */}
      {activeTab === "tree" ? (
        <ExpressionTreeView graph={graph} sessionId={params.sessionId} exprMode={exprMode} />
      ) : (
        <DagGraphView graph={graph} sessionId={params.sessionId} exprMode={exprMode} />
      )}
    </div>
  );
}
