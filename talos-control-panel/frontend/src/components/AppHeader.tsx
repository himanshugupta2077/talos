import { Link } from "react-router-dom";
import { useProject } from "../state/ProjectContext";
import HeaderClock from "./HeaderClock";
import HeaderCommandButton from "./HeaderCommandButton";
import HeaderFindings from "./HeaderFindings";
import HeaderProxyMenu from "./HeaderProxyMenu";
import HeaderRoleModule from "./HeaderRoleModule";
import HeaderSchedulerMenu from "./HeaderSchedulerMenu";
import HeaderSearch from "./HeaderSearch";
import ThemeToggle from "./ThemeToggle";

/**
 * Persistent global top header — runtime context + global actions.
 * Not primary application navigation (that stays in the left sidebar).
 *
 * Answers at a glance:
 *   1. What project / role / module context am I in?
 *   2. What is Talos doing now (proxy, scheduler, findings signal)?
 *   3. Quick access to search, activity console, theme.
 */
export default function AppHeader() {
  const { selected } = useProject();

  return (
    <header className="min-h-12 shrink-0 border-b border-base-300 flex items-center justify-between gap-3 px-3 py-1.5">
      {/* Context: project + active role/module */}
      <div className="flex items-center gap-1.5 min-w-0">
        <Link
          to="/projects"
          className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-base-300/50 min-w-0 max-w-[14rem]"
        >
          <span
            className={`inline-block w-2 h-2 rounded-full shrink-0 ${
              selected?.active ? "bg-success" : "bg-base-content/30"
            }`}
          />
          <span className="text-xs text-base-content/50 shrink-0 hidden sm:inline">
            Project:
          </span>
          <span className="text-sm font-medium truncate">
            {selected ? selected.name : "No project"}
          </span>
          {selected && !selected.active && (
            <span className="badge badge-ghost badge-xs shrink-0">inactive</span>
          )}
        </Link>

        <span className="text-base-content/20 select-none hidden sm:inline" aria-hidden>
          |
        </span>

        <HeaderRoleModule />
      </div>

      {/* Runtime observability + global utilities */}
      <div className="flex items-center gap-1.5 shrink-0 flex-wrap justify-end">
        <div className="flex items-center gap-1.5">
          <HeaderProxyMenu />
          <HeaderSchedulerMenu />
          <HeaderFindings />
        </div>

        <span className="text-base-content/20 select-none hidden md:inline mx-0.5" aria-hidden>
          |
        </span>

        <HeaderClock />

        <div className="flex items-center gap-1">
          <HeaderSearch />
          <HeaderCommandButton />
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
