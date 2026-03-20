/**
 * useVirtualizer 的替代实现，使用 @tanstack/virtual-core 直接构建。
 * 避免 @tanstack/react-virtual 默认的 flushSync 行为，
 * 后者在 React commit 阶段调用 flushSync 会阻塞主线程 100-700ms。
 */
import { useRef, useReducer, useEffect, useLayoutEffect, useCallback } from "react";
import {
  Virtualizer,
  elementScroll,
  observeElementOffset,
  observeElementRect,
  type VirtualizerOptions,
} from "@tanstack/virtual-core";

type PickRequired<T, K extends keyof T> = Omit<T, K> & Required<Pick<T, K>>;
type Options<TScroll extends Element, TItem extends Element = Element> = PickRequired<
  Partial<VirtualizerOptions<TScroll, TItem>>,
  "count" | "getScrollElement" | "estimateSize"
>;

export function useVirtualizerNoSync<
  TScroll extends Element,
  TItem extends Element = Element,
>(options: Options<TScroll, TItem>): Virtualizer<TScroll, TItem> {
  const [, rerender] = useReducer((c: number) => c + 1, 0);

  const resolvedOptions: VirtualizerOptions<TScroll, TItem> = {
    observeElementRect,
    observeElementOffset,
    scrollToFn: elementScroll,
    ...options,
    onChange: (instance, _sync) => {
      // 始终用异步 rerender，避免 flushSync 阻塞主线程
      rerender();
      options.onChange?.(instance, _sync);
    },
  };

  const instanceRef = useRef<Virtualizer<TScroll, TItem> | null>(null);
  if (!instanceRef.current) {
    instanceRef.current = new Virtualizer(resolvedOptions);
  }
  instanceRef.current.setOptions(resolvedOptions);

  useEffect(() => {
    return instanceRef.current!._didMount();
  }, []);

  useLayoutEffect(() => {
    instanceRef.current!._willUpdate();
  });

  return instanceRef.current;
}
