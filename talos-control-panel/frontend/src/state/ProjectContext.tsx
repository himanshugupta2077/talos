import { createContext, useContext, useEffect, useState, ReactNode, useCallback } from "react";
import { api } from "../api/client";
import { Project } from "../types";

interface ProjectContextValue {
  projects: Project[];
  selectedId: string | null;
  selected: Project | null;
  setSelectedId: (id: string | null) => void;
  refresh: () => Promise<void>;
  loading: boolean;
}

const ProjectContext = createContext<ProjectContextValue | null>(null);

const STORAGE_KEY = "talos-cp-selected-project";

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedId, setSelectedIdState] = useState<string | null>(
    () => localStorage.getItem(STORAGE_KEY)
  );
  const [loading, setLoading] = useState(true);

  const setSelectedId = useCallback((id: string | null) => {
    setSelectedIdState(id);
    if (id) localStorage.setItem(STORAGE_KEY, id);
    else localStorage.removeItem(STORAGE_KEY);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.get<{ projects: Project[]; active_project_id: string | null }>(
        "/api/projects"
      );
      setProjects(data.projects);
      setSelectedIdState((prev) => {
        if (prev && data.projects.some((p) => p.id === prev)) return prev;
        const fallback = data.active_project_id || data.projects[0]?.id || null;
        if (fallback) localStorage.setItem(STORAGE_KEY, fallback);
        return fallback;
      });
    } catch {
      setProjects([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const selected = projects.find((p) => p.id === selectedId) || null;

  return (
    <ProjectContext.Provider value={{ projects, selectedId, selected, setSelectedId, refresh, loading }}>
      {children}
    </ProjectContext.Provider>
  );
}

export function useProject() {
  const ctx = useContext(ProjectContext);
  if (!ctx) throw new Error("useProject must be used within ProjectProvider");
  return ctx;
}
