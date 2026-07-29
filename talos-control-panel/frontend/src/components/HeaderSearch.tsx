import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

type JumpItem = {
  id: string;
  label: string;
  path: string;
  group: string;
  keywords?: string;
};

/**
 * Destinations for the global jump palette. Kept in sync with sidebar domains;
 * runtime pages (Proxy, Scheduler) remain jumpable even when not top-level nav.
 */
const JUMP_ITEMS: JumpItem[] = [
  { id: "dashboard", label: "Dashboard", path: "/", group: "Overview" },
  { id: "projects", label: "Projects", path: "/projects", group: "Overview" },
  { id: "proxy", label: "Proxy", path: "/proxy", group: "Overview" },
  { id: "roles", label: "Roles & Modules", path: "/roles-modules", group: "Model", keywords: "role module" },
  {
    id: "access",
    label: "Access Model",
    path: "/access",
    group: "Model",
    keywords: "access matrix coverage signals client server bac idor allow deny",
  },
  { id: "auth", label: "Authentication", path: "/auth", group: "Model", keywords: "session cookie" },
  {
    id: "repeater",
    label: "Repeater",
    path: "/repeater",
    group: "Capture",
    keywords: "send burp edit once redo multi mode2",
  },
  { id: "endpoints", label: "Endpoints", path: "/endpoints", group: "Capture" },
  { id: "flows", label: "Flows", path: "/flows", group: "Capture" },
  { id: "mutations", label: "HTTP Rules", path: "/mutations", group: "Capture", keywords: "mutation header replace" },
  { id: "scheduler", label: "Scheduler", path: "/scheduler", group: "Testing" },
  {
    id: "testing",
    label: "Testing modules",
    path: "/testing",
    group: "Testing",
    keywords: "unauth bac secret passive active input validation modules attack",
  },
  {
    id: "testing-unauth",
    label: "Unauthenticated Execution",
    path: "/testing/unauth",
    group: "Testing",
    keywords: "auth bypass attack active",
  },
  {
    id: "testing-bac",
    label: "BAC",
    path: "/testing/bac",
    group: "Testing",
    keywords: "broken access control attack active idor",
  },
  {
    id: "testing-secrets",
    label: "Secret Detection",
    path: "/testing/secrets",
    group: "Testing",
    keywords: "secret passive disclosure attack",
  },
  {
    id: "testing-errors",
    label: "Error Intelligence",
    path: "/testing/errors",
    group: "Testing",
    keywords: "error stack sql exception disclosure traceback passive 500",
  },
  {
    id: "testing-iv",
    label: "Input Validation",
    path: "/testing/input-validation",
    group: "Testing",
    keywords: "iv xss sqli reflection probe characterization attack active",
  },
  { id: "findings", label: "Findings", path: "/findings", group: "Results" },
  { id: "console", label: "Console", path: "/console", group: "Results", keywords: "cli raw" },
  { id: "config", label: "Talos Configuration", path: "/talos-config", group: "Configuration" },
];

function matches(item: JumpItem, q: string): boolean {
  if (!q) return true;
  const hay = `${item.label} ${item.group} ${item.path} ${item.keywords || ""}`.toLowerCase();
  return hay.includes(q);
}

/**
 * Global search / jump palette. Opens via header button or Ctrl/Cmd+K.
 * Navigates to stable product destinations — not a full fuzzy command system.
 */
export default function HeaderSearch() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return JUMP_ITEMS.filter((item) => matches(item, q));
  }, [query]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query, open]);

  const close = useCallback(() => {
    setOpen(false);
    setQuery("");
    setActiveIndex(0);
  }, []);

  const go = useCallback(
    (item: JumpItem) => {
      navigate(item.path);
      close();
    },
    [navigate, close]
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) {
      // Focus after paint so the modal input receives the caret.
      const t = requestAnimationFrame(() => inputRef.current?.focus());
      return () => cancelAnimationFrame(t);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIndex((i) => Math.min(i + 1, Math.max(filtered.length - 1, 0)));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const item = filtered[activeIndex];
        if (item) go(item);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, filtered, activeIndex, close, go]);

  return (
    <>
      <button
        type="button"
        className="btn btn-xs btn-ghost border border-base-300 gap-1.5"
        aria-label="Search / jump (Ctrl+K)"
        onClick={() => setOpen(true)}
      >
        <svg
          className="h-3.5 w-3.5 opacity-70"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden
        >
          <circle cx="11" cy="11" r="7" />
          <path d="m20 20-3.5-3.5" />
        </svg>
        <span className="hidden sm:inline">Search</span>
        <kbd className="hidden md:inline kbd kbd-xs opacity-60">⌘K</kbd>
      </button>

      {open && (
        <div className="fixed inset-0 z-[60] flex items-start justify-center pt-[12vh] px-4">
          <button
            type="button"
            className="absolute inset-0 bg-base-content/40"
            aria-label="Close search"
            onClick={close}
          />
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Jump to page"
            className="relative w-full max-w-lg rounded-box border border-base-300 bg-base-100 shadow-2xl overflow-hidden"
          >
            <div className="flex items-center gap-2 border-b border-base-300 px-3">
              <svg
                className="h-4 w-4 opacity-50 shrink-0"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                aria-hidden
              >
                <circle cx="11" cy="11" r="7" />
                <path d="m20 20-3.5-3.5" />
              </svg>
              <input
                ref={inputRef}
                className="input input-ghost input-sm flex-1 min-w-0 focus:outline-none px-0"
                placeholder="Jump to page…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <kbd className="kbd kbd-xs opacity-50">esc</kbd>
            </div>
            <ul className="menu menu-sm p-2 max-h-80 overflow-y-auto">
              {filtered.length === 0 && (
                <li className="disabled">
                  <span className="text-base-content/50">No matches</span>
                </li>
              )}
              {filtered.map((item, index) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className={index === activeIndex ? "active" : ""}
                    onMouseEnter={() => setActiveIndex(index)}
                    onClick={() => go(item)}
                  >
                    <span className="truncate font-medium">{item.label}</span>
                    <span className="text-[11px] opacity-50 ml-auto shrink-0">
                      {item.group}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="border-t border-base-300 px-3 py-1.5 text-[10px] text-base-content/40 flex gap-3">
              <span>↑↓ navigate</span>
              <span>↵ open</span>
              <span>esc close</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
