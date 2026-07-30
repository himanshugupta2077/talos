import { STORAGE_MODE_COPY } from "../shared";
import type { IntruderStorageMode } from "../types";

const MODES: IntruderStorageMode[] = [
  "metrics_only",
  "sample_flows",
  "all_flows",
];

export default function StorageModeSelect({
  value,
  onChange,
}: {
  value: string;
  onChange: (m: IntruderStorageMode) => void;
}) {
  const current = (value || "metrics_only") as IntruderStorageMode;
  return (
    <div className="space-y-2">
      <div className="text-sm font-medium">Storage mode</div>
      <div className="flex flex-col gap-2">
        {MODES.map((m) => (
          <label
            key={m}
            className={`flex items-start gap-2 cursor-pointer rounded-md border px-3 py-2 text-sm ${
              current === m
                ? m === "all_flows"
                  ? "border-error/50 bg-error/5"
                  : "border-primary bg-primary/5"
                : "border-base-300"
            }`}
          >
            <input
              type="radio"
              className="radio radio-sm mt-0.5"
              name="storage-mode"
              checked={current === m}
              onChange={() => onChange(m)}
            />
            <span>
              <span className="font-medium mono text-xs">{m}</span>
              <span className="block text-xs text-base-content/60 mt-0.5">
                {STORAGE_MODE_COPY[m]}
              </span>
            </span>
          </label>
        ))}
      </div>
    </div>
  );
}
