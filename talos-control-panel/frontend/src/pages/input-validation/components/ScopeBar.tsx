import ParameterPicker from "../../../components/ParameterPicker";
import { inputClass, selectClass } from "../shared";

export type ScopeType = "none" | "host" | "endpoint" | "parameter";

export default function ScopeBar({
  projectId,
  scopeType,
  scopeValue,
  onTypeChange,
  onValueChange,
}: {
  projectId: string;
  scopeType: ScopeType;
  scopeValue: string;
  onTypeChange: (t: ScopeType) => void;
  onValueChange: (v: string) => void;
}) {
  return (
    <div className="flex gap-2 items-end flex-wrap">
      <select
        className={selectClass}
        value={scopeType}
        onChange={(e) => {
          onTypeChange(e.target.value as ScopeType);
          onValueChange("");
        }}
      >
        <option value="none">whole project</option>
        <option value="host">host</option>
        <option value="endpoint">endpoint</option>
        <option value="parameter">parameter</option>
      </select>
      {scopeType !== "none" && scopeType !== "parameter" && (
        <input
          className={`${inputClass} mono w-64`}
          value={scopeValue}
          onChange={(e) => onValueChange(e.target.value)}
          placeholder={scopeType}
        />
      )}
      {scopeType === "parameter" && (
        <ParameterPicker
          projectId={projectId}
          value={scopeValue}
          onChange={onValueChange}
        />
      )}
    </div>
  );
}

export function scopeBody(scopeType: ScopeType, scopeValue: string) {
  return {
    host: scopeType === "host" ? scopeValue : undefined,
    endpoint: scopeType === "endpoint" ? scopeValue : undefined,
    parameter: scopeType === "parameter" ? scopeValue : undefined,
  };
}
