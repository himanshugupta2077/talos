import { NoProjectNotice } from "../components/Common";
import { useProject } from "../state/ProjectContext";
import {
  ActivityRail,
  EndpointsPanel,
  FindingsPanel,
  FlowsPanel,
  HeroStrip,
  HttpRulesPanel,
  ProxyPanel,
  SchedulerPanel,
  SessionHealthPanel,
  TalosConfigPanel,
} from "./dashboard/panels";
import { useDashboardData } from "./dashboard/useDashboardData";
import { SkeletonPanel } from "./dashboard/widgets";

export default function Dashboard() {
  const { selected } = useProject();
  const { data, loading, error } = useDashboardData(selected?.id);

  if (!selected) return <NoProjectNotice />;

  if (loading && !data) {
    return (
      <div className="space-y-4">
        <SkeletonPanel />
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <SkeletonPanel />
          <SkeletonPanel />
          <SkeletonPanel />
          <SkeletonPanel />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SkeletonPanel />
          <SkeletonPanel />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="panel p-8 text-center">
        <p className="text-error text-sm mb-2">Failed to load dashboard</p>
        <p className="text-xs text-base-content/50 mono">{error}</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="panel p-8 text-center text-base-content/50 text-sm">
        No dashboard data for this project.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <HeroStrip data={data} />

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <FindingsPanel data={data} />
        <SchedulerPanel data={data} />
        <ProxyPanel data={data} />
        <SessionHealthPanel data={data} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <EndpointsPanel data={data} />
        <FlowsPanel data={data} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <HttpRulesPanel data={data} />
        <TalosConfigPanel data={data} />
      </div>

      <ActivityRail data={data} />

      {error && (
        <p className="text-[11px] text-warning text-center">
          Last refresh failed — showing previous snapshot ({error})
        </p>
      )}
    </div>
  );
}
