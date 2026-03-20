import { useRef, useCallback, useState } from "react";

interface Props {
  currentRow: number;
  maxRow: number;
  visibleRows: number;
  virtualTotalRows: number;
  trackHeight: number;
  onScroll: (row: number) => void;
}

export default function CustomScrollbar({
  currentRow, maxRow, visibleRows, virtualTotalRows, trackHeight, onScroll,
}: Props) {
  const [isDragging, setIsDragging] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const trackRef = useRef<HTMLDivElement>(null);
  const dragStartRef = useRef({ y: 0, row: 0 });

  const thumbHeight = Math.max(30, (visibleRows / Math.max(1, virtualTotalRows)) * trackHeight);
  const scrollableTrack = trackHeight - thumbHeight;
  const thumbTop = maxRow > 0 ? (currentRow / maxRow) * scrollableTrack : 0;

  const handleTrackClick = useCallback((e: React.MouseEvent) => {
    const track = trackRef.current;
    if (!track) return;
    const rect = track.getBoundingClientRect();
    const clickY = e.clientY - rect.top;
    const targetRow = Math.round((clickY - thumbHeight / 2) / scrollableTrack * maxRow);
    onScroll(Math.max(0, Math.min(maxRow, targetRow)));
  }, [maxRow, scrollableTrack, thumbHeight, onScroll]);

  const handleThumbMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
    dragStartRef.current = { y: e.clientY, row: currentRow };

    const onMove = (ev: MouseEvent) => {
      const dy = ev.clientY - dragStartRef.current.y;
      const dRow = Math.round((dy / scrollableTrack) * maxRow);
      const newRow = Math.max(0, Math.min(maxRow, dragStartRef.current.row + dRow));
      onScroll(newRow);
    };
    const onUp = () => {
      setIsDragging(false);
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [currentRow, maxRow, scrollableTrack, onScroll]);

  if (virtualTotalRows <= visibleRows) return null;

  return (
    <div
      ref={trackRef}
      onClick={handleTrackClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      style={{
        position: "absolute",
        top: 0,
        right: 0,
        width: 12,
        height: trackHeight,
        background: isHovered || isDragging ? "rgba(255,255,255,0.03)" : "transparent",
        zIndex: 10,
        cursor: "default",
      }}
    >
      <div
        onMouseDown={handleThumbMouseDown}
        style={{
          position: "absolute",
          top: thumbTop,
          right: 2,
          width: 8,
          height: thumbHeight,
          borderRadius: 4,
          background: isDragging || isHovered ? "var(--scrollbar-thumb-hover)" : "var(--scrollbar-thumb)",
          cursor: "pointer",
          transition: isDragging ? "none" : "background 0.15s",
        }}
      />
    </div>
  );
}
