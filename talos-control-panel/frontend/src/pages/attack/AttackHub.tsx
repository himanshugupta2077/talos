import { useCallback, useEffect, useMemo, useState } from "react";
import { useProject } from "../../state/ProjectContext";
import { api } from "../../api/client";
import { ModuleHelp, NoProjectNotice } from "../../components/Common";
import ModuleCard, { ModuleKpis } from "./ModuleCard";
import {
  ATTACK_CLASSES,
  ATTACK_MODULES,
  AttackClass,
  AttackModuleDef,
  filterModules,
  modulesForClass,
} from "./registry";

type ClassFilter = "all" | AttackClass;

/**
 * Testing modules hub — discover Passive vs Active modules, search, open workspaces.
 * Module-specific run/results live on /testing/:module paths.
 */
export default function AttackHub() {
  const { selected } = useProject();
  const [query, setQuery] = useState("");
  const [classFilter, setClassFilter] = useState<ClassFilter>("all");
  const [kpiMap, setKpiMap] = useState<Record<string, ModuleKpis>>({});

  const loadKpis = useCallback(() => {
    if (!selected) return;
    const pid = selected.id;

    // Unauth
    api
      .get<{ counts: Record<string, number> }>("/api/attack/unauth/summary", {
        project_id: pid,
      })
      .then((summary) => {
        const c = summary.counts || {};
        const bypass = c.BYPASS ?? 0;
        const secure = c.SECURE ?? 0;
        const unknown = c.UNKNOWN ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          unauth: {
            chips: [
              { label: "bypass", value: bypass, tone: bypass > 0 ? "danger" : "muted" },
              { label: "secure", value: secure, tone: "ok" },
              { label: "unknown", value: unknown, tone: "muted" },
            ],
          },
        }));
      })
      .catch(() => undefined);

    // BAC
    api
      .get<{ counts: Record<string, number> }>("/api/attack/bac/summary", {
        project_id: pid,
      })
      .then((r) => {
        const c = r.counts || {};
        const possible = c.POSSIBLE_BAC ?? 0;
        const secure = c.SECURE ?? 0;
        const unknown = c.UNKNOWN ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          bac: {
            chips: [
              {
                label: "possible",
                value: possible,
                tone: possible > 0 ? "danger" : "muted",
              },
              { label: "secure", value: secure, tone: "ok" },
              { label: "unknown", value: unknown, tone: "muted" },
            ],
          },
        }));
      })
      .catch(() => undefined);

    // Auth-Session Testing (active JWT mutation — K7 chips)
    api
      .get<{
        counts: Record<string, number>;
        candidates_by_status: Record<string, number>;
        targets_total?: number;
      }>("/api/attack/auth-session/summary", { project_id: pid })
      .then((summary) => {
        const c = summary.counts || {};
        const by = summary.candidates_by_status || {};
        const weak = c.WEAK_VALIDATION ?? 0;
        const pending = by.pending ?? 0;
        const approved = by.approved ?? 0;
        const ready = pending + approved;
        const targets = summary.targets_total ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          auth_session: {
            chips: [
              { label: "weak", value: weak, tone: weak > 0 ? "danger" : "muted" },
              {
                label: "targets",
                value: targets,
                tone: targets > 0 ? "ok" : "muted",
              },
              {
                label: "ready",
                value: ready,
                tone: ready > 0 ? "ok" : "muted",
              },
            ],
            // Full parity (Phase 5) — no inventory statusLine
          },
        }));
      })
      .catch(() => undefined);

    // Secrets (passive)
    api
      .get<{
        status: {
          enabled?: boolean;
          detections?: number;
          detections_with_finding?: number;
          documents?: number;
        };
      }>("/api/passive/overview", { project_id: pid, top_n: 1 })
      .then((r) => {
        const s = r.status || {};
        const detections = s.detections ?? 0;
        const findings = s.detections_with_finding ?? 0;
        const docs = s.documents ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          secrets: {
            chips: [
              {
                label: "detections",
                value: detections,
                tone: detections > 0 ? "warn" : "muted",
              },
              {
                label: "findings",
                value: findings,
                tone: findings > 0 ? "danger" : "muted",
              },
              { label: "docs", value: docs, tone: "muted" },
            ],
            // Only surface when disabled — "ready" is the default and noisy.
            statusLine: s.enabled === false ? "Scanner disabled" : undefined,
          },
        }));
      })
      .catch(() => {
        api
          .get<{
            enabled?: boolean;
            detections?: number;
            detections_with_finding?: number;
            documents?: number;
          }>("/api/passive/status", { project_id: pid })
          .then((s) => {
            const detections = s.detections ?? 0;
            const findings = s.detections_with_finding ?? 0;
            setKpiMap((prev) => ({
              ...prev,
              secrets: {
                chips: [
                  {
                    label: "detections",
                    value: detections,
                    tone: detections > 0 ? "warn" : "muted",
                  },
                  {
                    label: "findings",
                    value: findings,
                    tone: findings > 0 ? "danger" : "muted",
                  },
                  { label: "docs", value: s.documents ?? 0, tone: "muted" },
                ],
                statusLine: s.enabled === false ? "Scanner disabled" : undefined,
              },
            }));
          })
          .catch(() => undefined);
      });

    // Error Intelligence (passive)
    api
      .get<{
        status: {
          enabled?: boolean;
          clusters?: number;
          observations?: number;
          by_severity?: Record<string, number>;
        };
      }>("/api/error-intel/overview", { project_id: pid, top_n: 1 })
      .then((r) => {
        const s = r.status || {};
        const by = s.by_severity || {};
        const hot = (by.critical ?? 0) + (by.high ?? 0);
        const clusters = s.clusters ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          errors: {
            chips: [
              {
                label: "high+crit",
                value: hot,
                tone: hot > 0 ? "danger" : "muted",
              },
              {
                label: "clusters",
                value: clusters,
                tone: clusters > 0 ? "warn" : "muted",
              },
              {
                label: "obs",
                value: s.observations ?? 0,
                tone: "muted",
              },
            ],
            statusLine: s.enabled === false ? "Scanner disabled" : undefined,
          },
        }));
      })
      .catch(() => undefined);

    // URL Sink Discovery (passive inventory — prioritization only; K18 warn not danger)
    api
      .get<{
        nrs_count?: number;
        score_ge_70?: number;
        score_ge_threshold?: number;
        enabled_passive?: boolean;
      }>("/api/url-sink/status", { project_id: pid })
      .then((s) => {
        const nrs = s.nrs_count ?? 0;
        const hot = s.score_ge_70 ?? 0;
        const thr = s.score_ge_threshold ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          url_sinks: {
            chips: [
              {
                label: "nrs",
                value: nrs,
                tone: nrs > 0 ? "warn" : "muted",
              },
              {
                label: "score≥70",
                value: hot,
                tone: hot > 0 ? "warn" : "muted",
              },
              {
                label: "score≥thr",
                value: thr,
                tone: "muted",
              },
            ],
            statusLine:
              s.enabled_passive === false ? "Passive disabled" : undefined,
          },
        }));
      })
      .catch(() => undefined);

    // Input Validation (active)
    api
      .get<{
        status: {
          profiles?: number;
          confidence?: { candidates_total?: number; candidates_score_ge_60?: number };
          running?: number;
          queued?: number;
        };
      }>("/api/input-validation/overview", { project_id: pid, top_n: 1 })
      .then((r) => {
        const s = r.status || {};
        const profiles = s.profiles ?? 0;
        const candidates = s.confidence?.candidates_total ?? 0;
        const hot = s.confidence?.candidates_score_ge_60 ?? 0;
        const jobs = (s.running ?? 0) + (s.queued ?? 0);
        setKpiMap((prev) => ({
          ...prev,
          iv: {
            chips: [
              { label: "profiles", value: profiles, tone: profiles > 0 ? "ok" : "muted" },
              {
                label: "candidates",
                value: candidates,
                tone: candidates > 0 ? "warn" : "muted",
              },
              {
                label: "score≥60",
                value: hot,
                tone: hot > 0 ? "danger" : "muted",
              },
            ],
            statusLine: jobs > 0 ? `${jobs} job${jobs === 1 ? "" : "s"} in flight` : undefined,
          },
        }));
      })
      .catch(() => {
        api
          .get<{
            profiles?: number;
            confidence?: { candidates_total?: number; candidates_score_ge_60?: number };
          }>("/api/input-validation/status", { project_id: pid })
          .then((s) => {
            const profiles = s.profiles ?? 0;
            const candidates = s.confidence?.candidates_total ?? 0;
            const hot = s.confidence?.candidates_score_ge_60 ?? 0;
            setKpiMap((prev) => ({
              ...prev,
              iv: {
                chips: [
                  { label: "profiles", value: profiles, tone: profiles > 0 ? "ok" : "muted" },
                  {
                    label: "candidates",
                    value: candidates,
                    tone: candidates > 0 ? "warn" : "muted",
                  },
                  {
                    label: "score≥60",
                    value: hot,
                    tone: hot > 0 ? "danger" : "muted",
                  },
                ],
              },
            }));
          })
          .catch(() => undefined);
      });

    // CORS misconfiguration (active)
    api
      .get<{ counts: Record<string, number> }>("/api/attack/cors/summary", {
        project_id: pid,
      })
      .then((summary) => {
        const c = summary.counts || {};
        const issues = c.CORS_MISCONFIG ?? 0;
        const secure = c.SECURE ?? 0;
        const unknown = c.UNKNOWN ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          cors: {
            chips: [
              {
                label: "issues",
                value: issues,
                tone: issues > 0 ? "danger" : "muted",
              },
              { label: "secure", value: secure, tone: "ok" },
              { label: "unknown", value: unknown, tone: "muted" },
            ],
          },
        }));
      })
      .catch(() => undefined);

    // Intruder (active high-volume)
    api
      .get<{
        running: number;
        paused: number;
        interesting_total: number;
      }>("/api/intruder/summary", { project_id: pid })
      .then((r) => {
        const active = (r.running ?? 0) + (r.paused ?? 0);
        const interesting = r.interesting_total ?? 0;
        setKpiMap((prev) => ({
          ...prev,
          intruder: {
            chips: [
              {
                label: "active",
                value: active,
                tone: active > 0 ? "warn" : "muted",
              },
              {
                label: "interesting",
                value: interesting,
                tone: interesting > 0 ? "danger" : "muted",
              },
            ],
          },
        }));
      })
      .catch(() => undefined);
  }, [selected]);

  useEffect(() => {
    loadKpis();
  }, [loadKpis]);

  const matched = useMemo(() => filterModules(query), [query]);

  const visibleFor = (cls: AttackClass): AttackModuleDef[] => {
    const base =
      classFilter === "all" || classFilter === cls
        ? modulesForClass(cls)
        : [];
    if (!query.trim()) return base;
    const ids = new Set(matched.map((m) => m.id));
    return base.filter((m) => ids.has(m.id));
  };

  if (!selected) return <NoProjectNotice />;

  const passive = visibleFor("passive");
  const active = visibleFor("active");
  const totalVisible = passive.length + active.length;
  const showBothColumns = classFilter === "all";

  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h1 className="text-xl font-semibold">Attack Module</h1>
          <p className="text-sm text-base-content/60 mt-0.5 max-w-xl">
            Launch and review security tests. Passive modules observe captured
            traffic; Active modules send requests against the target.
          </p>
        </div>
        <ModuleHelp title="How Attack Module is organized">
          <p>
            <strong>Passive</strong> — scan what you already captured (secrets,
            error disclosures). Safe to leave enabled; no outbound validation.
          </p>
          <p>
            <strong>Active</strong> — enqueue crafted requests (auth bypass,
            BAC, input validation). Review risk and scope before running.
          </p>
          <p>
            Click a module card for run controls, decision filters, and results.
            Global triage stays on <strong>Findings</strong>.
          </p>
          <p>
            New modules appear here as cards under the right class. Available
            Active modules also list under <strong>Attack Module</strong> in
            the sidebar.
          </p>
        </ModuleHelp>
      </div>

      {/* Toolbar: class filter + search */}
      <div className="flex flex-wrap items-center gap-3 mb-6">
        <div role="tablist" className="tabs tabs-boxed tabs-sm">
          {(
            [
              { id: "all" as const, label: "All" },
              { id: "passive" as const, label: "Passive" },
              { id: "active" as const, label: "Active" },
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              className={`tab ${classFilter === t.id ? "tab-active" : ""}`}
              onClick={() => setClassFilter(t.id)}
            >
              {t.label}
              <span className="ml-1 opacity-50 text-[10px]">
                {t.id === "all"
                  ? ATTACK_MODULES.length
                  : modulesForClass(t.id).length}
              </span>
            </button>
          ))}
        </div>
        <label className="input input-sm input-bordered flex items-center gap-2 min-w-[14rem] flex-1 max-w-md">
          <span className="text-base-content/40 text-xs" aria-hidden>
            ⌕
          </span>
          <input
            type="search"
            className="grow bg-transparent outline-none text-sm"
            placeholder="Search modules (bac, secret, error, url, unauth, iv…)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search testing modules"
          />
          {query && (
            <button
              type="button"
              className="btn btn-ghost btn-xs px-1"
              onClick={() => setQuery("")}
              aria-label="Clear search"
            >
              ✕
            </button>
          )}
        </label>
      </div>

      {totalVisible === 0 && (
        <div className="panel p-8 text-center text-base-content/50 text-sm">
          No modules match “{query}”. Try another keyword or clear the filter.
        </div>
      )}

      <div
        className={
          showBothColumns
            ? "grid grid-cols-1 lg:grid-cols-2 gap-6"
            : "grid grid-cols-1 gap-6 max-w-2xl"
        }
      >
        {ATTACK_CLASSES.filter(
          (c) => classFilter === "all" || classFilter === c.id
        ).map((section) => {
          const items = visibleFor(section.id);
          if (query.trim() && items.length === 0) return null;
          return (
            <section key={section.id} aria-labelledby={`attack-class-${section.id}`}>
              <div className="mb-3">
                <h2
                  id={`attack-class-${section.id}`}
                  className="text-sm font-semibold uppercase tracking-wide text-base-content/70"
                >
                  {section.label}
                </h2>
                <p className="text-xs text-base-content/45 mt-0.5">{section.blurb}</p>
              </div>
              <div className="grid grid-cols-1 gap-3">
                {items.length === 0 && !query.trim() && (
                  <div className="panel p-4 text-xs text-base-content/40">
                    No {section.label.toLowerCase()} modules yet.
                  </div>
                )}
                {items.map((m) => (
                  <ModuleCard
                    key={m.id}
                    module={m}
                    kpis={m.kpi ? kpiMap[m.kpi] : null}
                  />
                ))}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}
