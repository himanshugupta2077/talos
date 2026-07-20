import { ReactNode, useEffect, useMemo, useState } from "react";

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
   * When set, enables per-column sort, show/hide, and drag-to-reorder, with
   * layout persisted to localStorage under this key so it survives reloads.
   */
  storageKey?: string;
}

interface SortState {
  key: string;
  dir: "asc" | "desc";
}

function loadLayout(storageKey: string | undefined, defaultOrder: string[]) {
  if (!storageKey) return { order: defaultOrder, hidden: [] as string[] };
  try {
    const raw = localStorage.getItem(`talos-cp-table:${storageKey}`);
    if (!raw) return { order: defaultOrder, hidden: [] as string[] };
    const parsed = JSON.parse(raw);
    const order: string[] = Array.isArray(parsed.order) ? parsed.order : defaultOrder;
    // Merge in any new columns that weren't there when the layout was saved.
    const merged = [...order.filter((k) => defaultOrder.includes(k)), ...defaultOrder.filter((k) => !order.includes(k))];
    return { order: merged, hidden: Array.isArray(parsed.hidden) ? parsed.hidden : [] };
  } catch {
    return { order: defaultOrder, hidden: [] as string[] };
  }
}

export default function DataTable<T>({
  columns, rows, rowKey, onRowClick, rowClassName, loading, emptyLabel = "Nothing here yet.", storageKey,
}: DataTableProps<T>) {
  const defaultOrder = useMemo(() => columns.map((c) => c.key), [columns]);
  const [order, setOrder] = useState<string[]>(() => loadLayout(storageKey, defaultOrder).order);
  const [hidden, setHidden] = useState<string[]>(() => loadLayout(storageKey, defaultOrder).hidden);
  const [sort, setSort] = useState<SortState | null>(null);
  const [dragKey, setDragKey] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  useEffect(() => {
    // Reset layout if the column set itself changed shape (different page).
    const { order: o, hidden: h } = loadLayout(storageKey, defaultOrder);
    setOrder(o);
    setHidden(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storageKey]);

  useEffect(() => {
    if (!storageKey) return;
    localStorage.setItem(`talos-cp-table:${storageKey}`, JSON.stringify({ order, hidden }));
  }, [storageKey, order, hidden]);

  const byKey = useMemo(() => new Map(columns.map((c) => [c.key, c])), [columns]);
  const visibleColumns = order.map((k) => byKey.get(k)).filter((c): c is Column<T> => !!c && !hidden.includes(c.key));

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

  return (
    <div className="panel">
      {storageKey && (
        <div className="flex justify-end px-2 pt-2">
          <div className="dropdown dropdown-end">
            <button
              tabIndex={0}
              className="btn btn-xs btn-ghost"
              onClick={() => setPickerOpen((v) => !v)}
              aria-label="Show/hide columns"
            >
              ⚙ Columns
            </button>
            {pickerOpen && (
              <div className="dropdown-content z-30 menu p-2 shadow bg-base-200 rounded-box w-56 border border-base-300">
                {columns.map((c) => (
                  <label key={c.key} className="flex items-center gap-2 py-1 px-2 text-sm cursor-pointer hover:bg-base-300/50 rounded">
                    <input
                      type="checkbox"
                      className="checkbox checkbox-xs"
                      checked={!hidden.includes(c.key)}
                      disabled={c.alwaysVisible}
                      onChange={() =>
                        setHidden((prev) =>
                          prev.includes(c.key) ? prev.filter((k) => k !== c.key) : [...prev, c.key]
                        )
                      }
                    />
                    {typeof c.header === "string" && c.header
                      ? c.header
                      : c.key}
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="table table-tight table-zebra">
          <thead>
            <tr>
              {visibleColumns.map((c) => (
                <th
                  key={c.key}
                  className={`text-xs uppercase tracking-wide text-base-content/60 select-none ${
                    c.sortable === false ? "" : "cursor-pointer"
                  } ${storageKey ? "cursor-grab" : ""}`}
                  draggable={!!storageKey}
                  onDragStart={() => setDragKey(c.key)}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={() => handleDrop(c.key)}
                  onClick={() => toggleSort(c)}
                >
                  {c.header}
                  {sort?.key === c.key && <span className="ml-1">{sort.dir === "asc" ? "▲" : "▼"}</span>}
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
                <td colSpan={visibleColumns.length} className="text-center py-8 text-base-content/50">
                  {emptyLabel}
                </td>
              </tr>
            )}
            {!loading &&
              sortedRows.map((row) => (
                <tr
                  key={rowKey(row)}
                  className={`${onRowClick ? "hover cursor-pointer" : ""} ${rowClassName ? rowClassName(row) : ""}`}
                  onClick={() => onRowClick?.(row)}
                >
                  {visibleColumns.map((c) => (
                    <td key={c.key} className={c.className}>
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
