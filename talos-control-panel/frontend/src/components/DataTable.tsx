import {
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export interface Column<T> {
  key: string;
  header: ReactNode;
  render?: (row: T) => ReactNode;
  className?: string;
  /** Value used for sorting. Defaults to (row as any)[key]. */
  sortValue?: (row: T) => string | number | null | undefined;
  /** Set false to disable sorting for this column (default: sortable). */
  sortable?: boolean;
  /** Column can't be hidden via the column picker (e.g. a trailing actions column). */
  alwaysVisible?: boolean;
  /** Default pixel width when no saved width exists. */
  defaultWidth?: number;
  /** Minimum pixel width when resizing (default 48). */
  minWidth?: number;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  rowClassName?: (row: T) => string;
  loading?: boolean;
  emptyLabel?: string;
  /**
   * When set, enables per-column sort, show/hide, drag-to-reorder, and column
   * width resize — layout persisted to localStorage under this key.
   */
  storageKey?: string;
}

interface SortState {
  key: string;
  dir: "asc" | "desc";
}

interface LayoutState {
  order: string[];
  hidden: string[];
  widths: Record<string, number>;
}

const DEFAULT_MIN_WIDTH = 48;
const DEFAULT_COL_WIDTH = 120;

function loadLayout(storageKey: string | undefined, defaultOrder: string[]): LayoutState {
  if (!storageKey) return { order: defaultOrder, hidden: [], widths: {} };
  try {
    const raw = localStorage.getItem(`talos-cp-table:${storageKey}`);
    if (!raw) return { order: defaultOrder, hidden: [], widths: {} };
    const parsed = JSON.parse(raw);
    const order: string[] = Array.isArray(parsed.order) ? parsed.order : defaultOrder;
    // Merge in any new columns that weren't there when the layout was saved.
    const merged = [
      ...order.filter((k) => defaultOrder.includes(k)),
      ...defaultOrder.filter((k) => !order.includes(k)),
    ];
    const widths =
      parsed.widths && typeof parsed.widths === "object" && !Array.isArray(parsed.widths)
        ? (parsed.widths as Record<string, number>)
        : {};
    return {
      order: merged,
      hidden: Array.isArray(parsed.hidden) ? parsed.hidden : [],
      widths,
    };
  } catch {
    return { order: defaultOrder, hidden: [], widths: {} };
  }
}

function headerLabel(col: Column<unknown>): string {
  if (typeof col.header === "string" && col.header) return col.header;
  return col.key;
}

export default function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  rowClassName,
  loading,
  emptyLabel = "Nothing here yet.",
  storageKey,
}: DataTableProps<T>) {
  const defaultOrder = useMemo(() => columns.map((c) => c.key), [columns]);
  const [order, setOrder] = useState<string[]>(
    () => loadLayout(storageKey, defaultOrder).order
  );
  const [hidden, setHidden] = useState<string[]>(
    () => loadLayout(storageKey, defaultOrder).hidden
  );
  const [widths, setWidths] = useState<Record<string, number>>(
    () => loadLayout(storageKey, defaultOrder).widths
  );
  const [sort, setSort] = useState<SortState | null>(null);
  const [dragKey, setDragKey] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const resizing = useRef<{
    key: string;
    startX: number;
    startW: number;
    minW: number;
  } | null>(null);

  useEffect(() => {
    const { order: o, hidden: h, widths: w } = loadLayout(storageKey, defaultOrder);
    setOrder(o);
    setHidden(h);
    setWidths(w);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storageKey]);

  useEffect(() => {
    if (!storageKey) return;
    localStorage.setItem(
      `talos-cp-table:${storageKey}`,
      JSON.stringify({ order, hidden, widths })
    );
  }, [storageKey, order, hidden, widths]);

  const byKey = useMemo(() => new Map(columns.map((c) => [c.key, c])), [columns]);
  const visibleColumns = order
    .map((k) => byKey.get(k))
    .filter((c): c is Column<T> => !!c && !hidden.includes(c.key));

  const colWidth = useCallback(
    (col: Column<T>) => {
      const saved = widths[col.key];
      if (typeof saved === "number" && saved > 0) return saved;
      return col.defaultWidth ?? DEFAULT_COL_WIDTH;
    },
    [widths]
  );

  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const col = byKey.get(sort.key);
    if (!col) return rows;
    const getVal = col.sortValue || ((row: T) => (row as any)[col.key]);
    const copy = [...rows];
    copy.sort((a, b) => {
      const av = getVal(a);
      const bv = getVal(b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      let cmp: number;
      if (typeof av === "number" && typeof bv === "number") cmp = av - bv;
      else cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sort.dir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [rows, sort, byKey]);

  function toggleSort(col: Column<T>) {
    if (col.sortable === false) return;
    setSort((prev) => {
      if (!prev || prev.key !== col.key) return { key: col.key, dir: "asc" };
      if (prev.dir === "asc") return { key: col.key, dir: "desc" };
      return null;
    });
  }

  function handleDrop(targetKey: string) {
    if (!dragKey || dragKey === targetKey) return;
    setOrder((prev) => {
      const next = prev.filter((k) => k !== dragKey);
      const idx = next.indexOf(targetKey);
      next.splice(idx, 0, dragKey);
      return next;
    });
    setDragKey(null);
  }

  const onResizeStart = (e: ReactMouseEvent, col: Column<T>) => {
    e.preventDefault();
    e.stopPropagation();
    const minW = col.minWidth ?? DEFAULT_MIN_WIDTH;
    resizing.current = {
      key: col.key,
      startX: e.clientX,
      startW: colWidth(col),
      minW,
    };
    document.body.classList.add("col-resizing");

    const onMove = (ev: MouseEvent) => {
      if (!resizing.current) return;
      const { key, startX, startW, minW: min } = resizing.current;
      const next = Math.max(min, startW + (ev.clientX - startX));
      setWidths((prev) => ({ ...prev, [key]: next }));
    };
    const onUp = () => {
      resizing.current = null;
      document.body.classList.remove("col-resizing");
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  function resetWidths() {
    setWidths({});
  }

  const totalMinWidth = visibleColumns.reduce((sum, c) => sum + colWidth(c), 0);

return (
    <div className="panel">
      {storageKey && (
        <div className="flex justify-between items-center px-2 pt-2 gap-2 flex-wrap border-b border-base-300/60 pb-2">
          <p className="text-[10px] text-base-content/45 px-1">
            Click a column header to sort · drag headers to reorder · drag column edges to
            resize · Columns menu to show/hide
          </p>
          <div className="flex items-center gap-1">
            <button
              type="button"
              className="btn btn-xs btn-ghost"
              onClick={resetWidths}
              title="Reset column widths to defaults"
            >
              Reset widths
            </button>
            <div className={`dropdown dropdown-end ${pickerOpen ? "dropdown-open" : ""}`}>
              <button
                tabIndex={0}
                type="button"
                className="btn btn-xs btn-ghost"
                onClick={() => setPickerOpen((v) => !v)}
                aria-label="Show/hide columns"
              >
                ⚙ Columns
              </button>
              {pickerOpen && (
                <div className="dropdown-content z-30 menu p-2 shadow bg-base-200 rounded-box w-56 border border-base-300">
                  {columns.map((c) => (
                    <label
                      key={c.key}
                      className="flex items-center gap-2 py-1 px-2 text-sm cursor-pointer hover:bg-base-300/50 rounded"
                    >
                      <input
                        type="checkbox"
                        className="checkbox checkbox-xs"
                        checked={!hidden.includes(c.key)}
                        disabled={c.alwaysVisible}
                        onChange={() =>
                          setHidden((prev) =>
                            prev.includes(c.key)
                              ? prev.filter((k) => k !== c.key)
                              : [...prev, c.key]
                          )
                        }
                      />
                      {headerLabel(c as Column<unknown>)}
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      <div className="overflow-x-auto overflow-y-visible">
        <table
          className="table table-tight table-zebra table-boxed w-full"
          style={{ tableLayout: "fixed", minWidth: totalMinWidth }}
        >
          <colgroup>
            {visibleColumns.map((c) => (
              <col key={c.key} style={{ width: colWidth(c) }} />
            ))}
          </colgroup>
          <thead>
            <tr>
              {visibleColumns.map((c) => (
                <th
                  key={c.key}
                  className={`relative text-xs uppercase tracking-wide text-base-content/70 select-none ${
                    c.sortable === false ? "" : "cursor-pointer"
                  } ${storageKey ? "cursor-grab" : ""}`}
                  style={{ width: colWidth(c), minWidth: c.minWidth ?? DEFAULT_MIN_WIDTH }}
                  draggable={!!storageKey && !resizing.current}
                  onDragStart={() => setDragKey(c.key)}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={() => handleDrop(c.key)}
                  onClick={() => toggleSort(c)}
                  title={
                    c.sortable === false
                      ? storageKey
                        ? "Drag header to reorder · drag right edge to resize"
                        : undefined
                      : storageKey
                        ? "Click to sort · drag header to reorder · drag right edge to resize"
                        : "Click to sort"
                  }
                >
                  <span className="pr-2 inline-flex items-center gap-0.5 min-w-0">
                    <span className="truncate">{c.header}</span>
                    {sort?.key === c.key && (
                      <span className="ml-0.5 shrink-0">
                        {sort.dir === "asc" ? "▲" : "▼"}
                      </span>
                    )}
                  </span>
                  {/* Visible resize handle on every column */}
                  <span
                    role="separator"
                    aria-orientation="vertical"
                    aria-label={`Resize ${headerLabel(c as Column<unknown>)} column`}
                    className="col-resize-handle"
                    onMouseDown={(e) => onResizeStart(e, c)}
                    onClick={(e) => e.stopPropagation()}
                    onDragStart={(e) => e.preventDefault()}
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={visibleColumns.length} className="text-center py-8">
                  <span className="loading loading-spinner loading-sm" />
                </td>
              </tr>
            )}
            {!loading && sortedRows.length === 0 && (
              <tr>
                <td
                  colSpan={visibleColumns.length}
                  className="text-center py-8 text-base-content/50"
                >
                  {emptyLabel}
                </td>
              </tr>
            )}
            {!loading &&
              sortedRows.map((row) => (
                <tr
                  key={rowKey(row)}
                  className={`${onRowClick ? "hover cursor-pointer" : ""} ${
                    rowClassName ? rowClassName(row) : ""
                  }`}
                  onClick={() => onRowClick?.(row)}
                >
                  {visibleColumns.map((c) => (
                    <td
                      key={c.key}
                      className={`${
                        c.key === "actions" ? "overflow-visible" : "overflow-hidden"
                      } ${c.className || ""}`}
                      style={{
                        width: colWidth(c),
                        minWidth: c.minWidth ?? DEFAULT_MIN_WIDTH,
                      }}
                    >
                      {c.render ? c.render(row) : (row as any)[c.key]}
                    </td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
