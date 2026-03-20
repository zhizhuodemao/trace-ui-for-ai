import { useState, useMemo, useCallback } from "react";
import type { CallTreeNodeDto } from "../types/trace";

/** resolveVirtualIndex 返回类型 */
export type ResolvedRow =
  | { type: "line"; seq: number }
  | { type: "summary"; nodeId: number; funcAddr: string; lineCount: number; entrySeq: number }
  | { type: "hidden-summary"; seqs: number[]; count: number };

/** 折叠区间（按 startSeq 排序） */
interface FoldRange {
  startSeq: number;   // entry_seq + 1（第一个隐藏行）
  endSeq: number;     // exit_seq（最后一个隐藏行）
  nodeId: number;
  funcAddr: string;
  lineCount: number;  // exit_seq - entry_seq + 1（含 BL 行的总行数）
  entrySeq: number;   // BL 行的 seq（= entry_seq）
}

/**
 * 收集"顶层可见"的折叠区间。
 * 当父函数被折叠时，其内部的子折叠不可见，不出现在结果中。
 */
function collectVisibleFoldRanges(
  foldedNodes: Set<number>,
  nodeMap: Map<number, CallTreeNodeDto>,
): FoldRange[] {
  const ranges: FoldRange[] = [];

  function walk(nodeId: number) {
    const node = nodeMap.get(nodeId);
    if (!node) return;

    if (foldedNodes.has(nodeId) && nodeId !== 0) {
      const hiddenCount = node.exit_seq - node.entry_seq;
      if (hiddenCount > 0) {
        ranges.push({
          startSeq: node.entry_seq + 1,
          endSeq: node.exit_seq,
          nodeId: node.id,
          funcAddr: node.func_addr,
          lineCount: node.exit_seq - node.entry_seq + 1,
          entrySeq: node.entry_seq,
        });
      }
      return;
    }

    for (const childId of node.children_ids) {
      walk(childId);
    }
  }

  walk(0);
  ranges.sort((a, b) => a.startSeq - b.startSeq);
  return ranges;
}

export function useFoldState(
  nodeMap: Map<number, CallTreeNodeDto>,
  totalLines: number,
) {
  const [foldedNodes, setFoldedNodes] = useState<Set<number>>(new Set());

  const blLineMap = useMemo(() => {
    const map = new Map<number, CallTreeNodeDto>();
    for (const node of nodeMap.values()) {
      if (node.id !== 0) {
        map.set(node.entry_seq, node);
      }
    }
    return map;
  }, [nodeMap]);

  const foldedRanges = useMemo(
    () => collectVisibleFoldRanges(foldedNodes, nodeMap),
    [foldedNodes, nodeMap],
  );

  /**
   * 虚拟总行数。
   * 每个折叠：隐藏 (endSeq - startSeq + 1) 行，插入 1 行摘要。
   * 净减少 = hiddenCount - 1
   */
  const virtualTotalRows = useMemo(() => {
    let netReduction = 0;
    for (const range of foldedRanges) {
      const hiddenCount = range.endSeq - range.startSeq + 1;
      netReduction += hiddenCount - 1; // -1 因为插入了 1 行摘要
    }
    return totalLines - netReduction;
  }, [foldedRanges, totalLines]);

  /**
   * 虚拟索引 → 真实内容。
   *
   * 虚拟空间布局（以折叠 [entry=100, exit=200] 为例）：
   *   virtual 0-100: seq 0-100 (含 BL 行 seq=100)
   *   virtual 101: SUMMARY（摘要行，替代 seq 101-200）
   *   virtual 102+: seq 201+
   *
   * 每个折叠在虚拟空间中占 1 行摘要，偏移 = hiddenCount - 1
   */
  const resolveVirtualIndex = useCallback(
    (virtualIdx: number): ResolvedRow => {
      if (foldedRanges.length === 0) {
        return { type: "line", seq: virtualIdx };
      }

      let offset = 0; // 累计净减少量
      for (const range of foldedRanges) {
        const hiddenCount = range.endSeq - range.startSeq + 1;
        // 摘要行在虚拟空间中的位置 = range.startSeq - offset
        const summaryVirtual = range.startSeq - offset;

        if (virtualIdx < summaryVirtual) {
          return { type: "line", seq: virtualIdx + offset };
        }

        if (virtualIdx === summaryVirtual) {
          return {
            type: "summary",
            nodeId: range.nodeId,
            funcAddr: range.funcAddr,
            lineCount: range.lineCount,
            entrySeq: range.entrySeq,
          };
        }

        // virtualIdx > summaryVirtual: 在摘要之后
        offset += hiddenCount - 1; // 净偏移
      }

      return { type: "line", seq: virtualIdx + offset };
    },
    [foldedRanges],
  );

  /**
   * 真实 seq → 虚拟索引。
   * 如果 seq 在折叠区间内，返回该折叠的摘要行位置。
   */
  const seqToVirtualIndex = useCallback(
    (seq: number): number => {
      if (foldedRanges.length === 0) return seq;

      let offset = 0;
      for (const range of foldedRanges) {
        const hiddenCount = range.endSeq - range.startSeq + 1;

        if (seq < range.startSeq) {
          return seq - offset;
        }
        if (seq >= range.startSeq && seq <= range.endSeq) {
          // seq 在折叠区间内，返回摘要行的虚拟位置
          return range.startSeq - offset;
        }
        offset += hiddenCount - 1;
      }

      return seq - offset;
    },
    [foldedRanges],
  );

  const toggleFold = useCallback((nodeId: number) => {
    setFoldedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  }, []);

  const isFolded = useCallback(
    (nodeId: number) => foldedNodes.has(nodeId),
    [foldedNodes],
  );

  /** 展开所有包含 seq 的折叠区间（含嵌套），使该行在虚拟空间中可见 */
  const ensureSeqVisible = useCallback((seq: number) => {
    setFoldedNodes(prev => {
      const toRemove: number[] = [];
      for (const nodeId of prev) {
        const node = nodeMap.get(nodeId);
        // entry_seq 是 BL 行本身（不隐藏），隐藏范围是 (entry_seq, exit_seq]
        if (node && seq > node.entry_seq && seq <= node.exit_seq) {
          toRemove.push(nodeId);
        }
      }
      if (toRemove.length === 0) return prev;
      const next = new Set(prev);
      for (const id of toRemove) next.delete(id);
      return next;
    });
  }, [nodeMap]);

  return {
    blLineMap,
    virtualTotalRows,
    resolveVirtualIndex,
    seqToVirtualIndex,
    toggleFold,
    isFolded,
    ensureSeqVisible,
    foldedNodes,
  };
}
