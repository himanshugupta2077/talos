import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import AppHeader from "./AppHeader";
import CommandDrawer from "./CommandDrawer";
import ToastStack from "./ToastStack";
import { availableModulesForClass } from "../pages/attack/registry";

type SidebarMode = "expanded" | "icons" | "auto";

const SIDEBAR_MODE_KEY = "talos-cp-sidebar-mode";
const COLLAPSE_DELAY_MS = 280;

type NavTone = "danger";
type NavItem = {
  to: string;
  label: string;
  icon: IconName;
  tone?: NavTone;
  /** Exact path match (hub). Default is prefix match for nested workspaces. */
  end?: boolean;
  children?: NavChild[];
};
type NavChild = { to: string; label: string };
type NavGroup = { label: string; items: NavItem[] };

const ACTIVE_ATTACK_NAV: NavChild[] = availableModulesForClass("active").map((m) => ({
  to: m.path,
  label: m.name,
}));

type IconName =
  | "dashboard"
  | "projects"
  | "proxy"
  | "roles"
  | "access"
  | "auth"
  | "endpoints"
  | "flows"
  | "repeater"
  | "mutations"
  | "scheduler"
  | "attack"
  | "findings"
  | "console"
  | "config"
  | "panelLeft"
  | "panelRight"
  | "auto"
  | "chevronLeft"
  | "chevronRight";

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: "dashboard" },
      { to: "/projects", label: "Projects", icon: "projects" },
      { to: "/proxy", label: "Proxy", icon: "proxy" },
    ],
  },
  {
    label: "Model",
    items: [
      { to: "/roles-modules", label: "Roles & Modules", icon: "roles" },
      { to: "/access", label: "Access Model", icon: "access" },
      { to: "/auth", label: "Auth", icon: "auth" },
    ],
  },
  {
    label: "Capture",
    items: [
      { to: "/repeater", label: "Repeater", icon: "repeater" },
      { to: "/endpoints", label: "Endpoints", icon: "endpoints" },
      { to: "/flows", label: "Flows", icon: "flows" },
      { to: "/mutations", label: "HTTP Rules", icon: "mutations" },
    ],
  },
  {
    label: "Testing",
    items: [
      { to: "/scheduler", label: "Scheduler", icon: "scheduler" },
      {
        to: "/testing",
        label: "Attack Module",
        icon: "attack",
        tone: "danger",
        end: true,
        children: ACTIVE_ATTACK_NAV,
      },
    ],
  },
  {
    label: "Configuration",
    items: [
      { to: "/talos-config", label: "Talos Configuration", icon: "config" },
    ],
  },
  {
    label: "Results",
    items: [
      { to: "/findings", label: "Findings", icon: "findings" },
      { to: "/console", label: "Console", icon: "console" },
    ],
  },
];

const ICON_PATHS: Record<IconName, ReactNode> = {
  dashboard: (
    <>
      <path d="M3 10.5 12 3l9 7.5" />
      <path d="M5 10v10h14V10" />
      <path d="M10 20v-6h4v6" />
    </>
  ),
  projects: (
    <>
      <path d="M4 7h16v12H4z" />
      <path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    </>
  ),
  proxy: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" />
    </>
  ),
  roles: (
    <>
      <circle cx="9" cy="8" r="3" />
      <circle cx="16" cy="9" r="2.5" />
      <path d="M3 19c0-2.8 2.7-5 6-5s6 2.2 6 5" />
      <path d="M15 14c2.2.3 4 1.8 4 4" />
    </>
  ),
  access: (
    <>
      <path d="M12 3 4 7v5c0 5 3.4 8.4 8 9 4.6-.6 8-4 8-9V7l-8-4z" />
      <path d="M9.5 12.5 11 14l3.5-3.5" />
    </>
  ),
  auth: (
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </>
  ),
  endpoints: (
    <>
      <path d="M8 7h8v10H8z" />
      <path d="M8 10h8M8 14h8" />
      <path d="M4 9v6M20 9v6" />
    </>
  ),
  flows: (
    <>
      <circle cx="6" cy="6" r="2.5" />
      <circle cx="18" cy="12" r="2.5" />
      <circle cx="6" cy="18" r="2.5" />
      <path d="M8.2 7.5 15.5 11M8.2 16.5 15.5 13" />
    </>
  ),
  repeater: (
    <>
      <path d="M4 7h16v10H4z" />
      <path d="M7 10h6M7 13h10" />
      <path d="M17 4v3M17 17v3" />
    </>
  ),
  mutations: (
    <>
      <path d="M4 20 14 10" />
      <path d="M12.5 8.5 15.5 11.5" />
      <path d="M14 4l6 6" />
      <path d="M4 20h6" />
    </>
  ),
  scheduler: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 8v4.5l3 2" />
    </>
  ),
  attack: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4" />
      <circle cx="12" cy="12" r="1" />
      <path d="M12 2v2M12 20v2M2 12h2M20 12h2" />
    </>
  ),
  findings: (
    <>
      <path d="M12 3 3 19h18L12 3z" />
      <path d="M12 9v5" />
      <path d="M12 16.5h.01" />
    </>
  ),
  console: (
    <>
      <path d="M4 6h16v12H4z" />
      <path d="M7 10l3 2-3 2" />
      <path d="M12 14h5" />
    </>
  ),
  config: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.05 5.05l1.56 1.56M17.4 17.4l1.55 1.55M18.95 5.05l-1.56 1.56M6.61 17.4l-1.56 1.55" />
    </>
  ),
  panelLeft: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M9 4v16" />
    </>
  ),
  panelRight: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M15 4v16" />
    </>
  ),
  auto: (
    <>
      <path d="M4 8h10" />
      <path d="M14 8 11 5M14 8l-3 3" />
      <path d="M20 16H10" />
      <path d="M10 16l3-3M10 16l3 3" />
    </>
  ),
  chevronLeft: <path d="M14 6 8 12l6 6" />,
  chevronRight: <path d="M10 6l6 6-6 6" />,
};

function navItemToneClass(tone: NavTone | undefined, isActive: boolean): string {
  if (tone === "danger") {
    return isActive
      ? "bg-error/15 text-error font-medium"
      : "text-error/80 hover:bg-error/10 hover:text-error";
  }
  return isActive
    ? "bg-primary/10 text-primary font-medium"
    : "text-base-content/80 hover:bg-base-300/50";
}

function sectionIsActive(pathname: string, item: NavItem): boolean {
  // Hub items use `end` so the parent is not "current" on a child page, but the
  // icon rail still needs a section highlight for any nested /testing/* path.
  if (item.end && !item.children?.length) return pathname === item.to;
  return pathname === item.to || pathname.startsWith(`${item.to}/`);
}

function Icon({ name, className = "h-4 w-4" }: { name: IconName; className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

function readSidebarMode(): SidebarMode {
  const raw = localStorage.getItem(SIDEBAR_MODE_KEY);
  if (raw === "expanded" || raw === "icons" || raw === "auto") return raw;
  return "expanded";
}

export function SidebarNav({ visuallyExpanded }: { visuallyExpanded: boolean }) {
  const location = useLocation();
  return (
    <nav
      className={`flex-1 overflow-y-auto overflow-x-hidden py-2 ${
        visuallyExpanded ? "" : "sidebar-rail-scroll"
      }`}
    >
      {NAV_GROUPS.map((group, groupIndex) => (
        <div key={group.label} className="mb-3">
          {visuallyExpanded ? (
            <div className="px-4 py-1 text-[11px] uppercase tracking-wider text-base-content/40">
              {group.label}
            </div>
          ) : (
            groupIndex > 0 && (
              <div className="mx-3 mb-1.5 border-t border-base-300/70" aria-hidden />
            )
          )}
          {group.items.map((item) => {
            const inSection = sectionIsActive(location.pathname, item);
            const showChildren = visuallyExpanded && (item.children?.length ?? 0) > 0;
            return (
              <div key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end ?? item.to === "/"}
                  aria-label={item.label}
                  title={visuallyExpanded ? undefined : item.label}
                  className={({ isActive }) =>
                    `group relative flex items-center text-sm transition-colors ${
                      visuallyExpanded
                        ? "mx-2 gap-3 px-2.5 py-1.5 rounded-md"
                        : "mx-2 justify-center py-2 rounded-md"
                    } ${navItemToneClass(item.tone, isActive || (!visuallyExpanded && inSection))}`
                  }
                >
                  {({ isActive }) => {
                    const marked = isActive || (!visuallyExpanded && inSection);
                    const accent = item.tone === "danger" ? "bg-error" : "bg-primary";
                    return (
                      <>
                        {!visuallyExpanded && marked && (
                          <span
                            className={`absolute left-0 top-1/2 -translate-y-1/2 h-5 w-0.5 rounded-r ${accent}`}
                          />
                        )}
                        {visuallyExpanded && isActive && (
                          <span
                            className={`absolute right-0 top-1/2 -translate-y-1/2 h-5 w-0.5 rounded-l ${accent}`}
                          />
                        )}
                        <Icon name={item.icon} className="h-[1.125rem] w-[1.125rem] shrink-0" />
                        {visuallyExpanded && <span className="truncate">{item.label}</span>}
                      </>
                    );
                  }}
                </NavLink>
                {showChildren && (
                  <div className="mb-0.5 ml-5 mr-2 border-l border-error/25 pl-2">
                    {item.children!.map((child) => (
                      <NavLink
                        key={child.to}
                        to={child.to}
                        aria-label={child.label}
                        title={child.label}
                        className={({ isActive }) =>
                          `flex items-center rounded-md px-2 py-1 text-[12px] leading-snug transition-colors ${navItemToneClass(
                            item.tone,
                            isActive,
                          )}`
                        }
                      >
                        {({ isActive }) => (
                          <span className={isActive ? "font-medium" : ""}>{child.label}</span>
                        )}
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

export default function Layout() {
  const [mode, setMode] = useState<SidebarMode>(readSidebarMode);
  const [hovered, setHovered] = useState(false);
  const collapseTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    localStorage.setItem(SIDEBAR_MODE_KEY, mode);
  }, [mode]);

  useEffect(() => {
    return () => {
      if (collapseTimer.current) clearTimeout(collapseTimer.current);
    };
  }, []);

  const clearCollapseTimer = useCallback(() => {
    if (collapseTimer.current) {
      clearTimeout(collapseTimer.current);
      collapseTimer.current = null;
    }
  }, []);

  const onSidebarEnter = useCallback(() => {
    clearCollapseTimer();
    setHovered(true);
  }, [clearCollapseTimer]);

  const onSidebarLeave = useCallback(() => {
    clearCollapseTimer();
    // Short delay so moving between icon/label doesn't flash-collapse in auto mode.
    collapseTimer.current = setTimeout(() => setHovered(false), COLLAPSE_DELAY_MS);
  }, [clearCollapseTimer]);

  // Auto expands as an overlay so the main column doesn't reflow on every hover.
  const visuallyExpanded = mode === "expanded" || (mode === "auto" && hovered);
  const reservedWide = mode === "expanded";
  const isOverlayExpand = mode === "auto" && hovered;

  const setModeAndPersist = (next: SidebarMode) => {
    setMode(next);
    if (next !== "auto") setHovered(false);
    // Close daisyUI dropdown by blurring the open menu trigger.
    if (document.activeElement instanceof HTMLElement) {
      document.activeElement.blur();
    }
  };

  const togglePinned = () => {
    // Quick toggle: expanded ↔ icons. Leaving auto always pins open first.
    if (mode === "expanded") setModeAndPersist("icons");
    else setModeAndPersist("expanded");
  };

  const modeLabel =
    mode === "expanded" ? "Expanded" : mode === "icons" ? "Icons only" : "Auto-hide";

  return (
    <div className="flex h-screen overflow-hidden bg-base-100">
      {/* Layout spacer — only full width when pinned expanded; auto uses icon rail width. */}
      <div
        className={`shrink-0 transition-[width] duration-200 ease-out ${
          reservedWide ? "w-60" : "w-16"
        }`}
        aria-hidden
      />

      <aside
        className={`fixed inset-y-0 left-0 z-30 flex flex-col border-r border-base-300 bg-base-200 transition-[width,box-shadow] duration-200 ease-out ${
          visuallyExpanded ? "w-60" : "w-16"
        } ${isOverlayExpand ? "shadow-xl shadow-base-content/10" : ""}`}
        onMouseEnter={onSidebarEnter}
        onMouseLeave={onSidebarLeave}
        onFocusCapture={onSidebarEnter}
        onBlurCapture={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
            onSidebarLeave();
          }
        }}
      >
        <div
          className={`border-b border-base-300 flex items-center ${
            visuallyExpanded ? "gap-2 px-4 py-4" : "justify-center px-0 py-4"
          }`}
        >
          <div
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-primary font-bold text-sm"
            aria-hidden
          >
            T
          </div>
          {visuallyExpanded && (
            <div className="min-w-0 overflow-hidden transition-opacity duration-150 opacity-100">
              <div className="font-bold text-lg tracking-tight leading-tight whitespace-nowrap">Talos</div>
              <div className="text-xs text-base-content/50 whitespace-nowrap">Control Panel</div>
            </div>
          )}
        </div>

        <SidebarNav visuallyExpanded={visuallyExpanded} />

        {/* Sidebar chrome: pin/collapse + mode menu */}
        <div
          className={`border-t border-base-300 p-2 flex items-center gap-1 ${
            visuallyExpanded ? "justify-between" : "flex-col"
          }`}
        >
          <button
            type="button"
            className="btn btn-ghost btn-sm btn-square"
            onClick={togglePinned}
            aria-label={mode === "expanded" ? "Collapse to icons" : "Expand sidebar"}
          >
            <Icon name={mode === "expanded" ? "chevronLeft" : "chevronRight"} className="h-4 w-4" />
          </button>

          <div className={`dropdown ${visuallyExpanded ? "dropdown-top dropdown-end" : "dropdown-top dropdown-end"}`}>
            <button
              type="button"
              tabIndex={0}
              className={`btn btn-ghost btn-sm gap-1.5 ${visuallyExpanded ? "" : "btn-square"} ${
                mode === "auto" ? "text-primary" : ""
              }`}
              aria-label={`Sidebar view: ${modeLabel}. Open menu to change.`}
            >
              <Icon name={mode === "auto" ? "auto" : mode === "icons" ? "panelLeft" : "panelRight"} className="h-4 w-4" />
              {visuallyExpanded && <span className="text-xs font-normal">{modeLabel}</span>}
            </button>
            <ul
              tabIndex={0}
              className="dropdown-content menu bg-base-100 rounded-box z-50 w-52 p-2 shadow-lg border border-base-300 mb-1"
            >
              <li className="menu-title px-2 pt-1 pb-0">
                <span className="text-[11px]">Sidebar view</span>
              </li>
              <li>
                <button
                  type="button"
                  className={mode === "expanded" ? "active" : ""}
                  onClick={() => setModeAndPersist("expanded")}
                >
                  <Icon name="panelRight" className="h-4 w-4" />
                  <span>
                    Expanded
                    <span className="block text-[11px] font-normal opacity-60">Full labels</span>
                  </span>
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className={mode === "icons" ? "active" : ""}
                  onClick={() => setModeAndPersist("icons")}
                >
                  <Icon name="panelLeft" className="h-4 w-4" />
                  <span>
                    Icons only
                    <span className="block text-[11px] font-normal opacity-60">Narrow rail</span>
                  </span>
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className={mode === "auto" ? "active" : ""}
                  onClick={() => setModeAndPersist("auto")}
                >
                  <Icon name="auto" className="h-4 w-4" />
                  <span>
                    Auto-hide
                    <span className="block text-[11px] font-normal opacity-60">Expand on hover</span>
                  </span>
                </button>
              </li>
            </ul>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0 min-h-0 relative">
        <AppHeader />
        <main className="flex-1 overflow-y-auto p-6 min-h-0">
          <Outlet />
        </main>
        {/* Bottom-docked activity console (Chrome DevTools style); overlays in auto-hide. */}
        <CommandDrawer />
      </div>
      <ToastStack />
    </div>
  );
}
