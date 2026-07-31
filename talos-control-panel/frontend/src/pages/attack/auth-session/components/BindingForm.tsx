import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAction } from "../../../../hooks/useAction";
import { api } from "../../../../api/client";
import { FieldHint, Section } from "../../../../components/Common";
import { inputClass, selectClass } from "../shared";

type Artifact = { type: string; name: string };

/**
 * Bind form: type=jwt only; location header|cookie; name from auth_config picker.
 */
export default function BindingForm({
  projectId,
  artifacts,
  onDone,
}: {
  projectId: string;
  artifacts: Artifact[];
  onDone: () => void;
}) {
  const [location, setLocation] = useState<"header" | "cookie">("header");
  const [name, setName] = useState("");
  const [role, setRole] = useState("");
  const [configJson, setConfigJson] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  const namesForLocation = useMemo(
    () =>
      artifacts
        .filter((a) => a.type === location)
        .map((a) => a.name)
        .sort(),
    [artifacts, location]
  );

  useEffect(() => {
    if (name && !namesForLocation.includes(name)) {
      setName("");
    }
  }, [location, namesForLocation, name]);

  const bind = useAction("Bind auth-session field", () => {
    const body: Record<string, unknown> = {
      auth_type: "jwt",
    };
    if (location === "header") body.header = name;
    else body.cookie = name;
    if (role.trim()) body.role = role.trim();
    if (configJson.trim()) body.config_json = configJson.trim();
    return api.post("/api/attack/auth-session/bindings", body, {
      project_id: projectId,
    });
  });

  const emptyForLocation = namesForLocation.length === 0;

  return (
    <Section title="Bind JWT field">
      <p className="text-xs text-base-content/60 mb-3">
        Bind an auth_config header or cookie name to the JWT auth type so generate
        knows which presented credential to mutate. Names must already exist on
        the{" "}
        <Link className="link link-primary" to="/auth">
          Auth page
        </Link>
        .
      </p>

      <div className="flex flex-wrap items-end gap-3 mb-3">
        <label className="form-control">
          <span className="label-text text-xs">Location</span>
          <select
            className={selectClass}
            value={location}
            onChange={(e) => setLocation(e.target.value as "header" | "cookie")}
          >
            <option value="header">header</option>
            <option value="cookie">cookie</option>
          </select>
        </label>

        <label className="form-control min-w-[12rem]">
          <span className="label-text text-xs">Name (from auth_config)</span>
          <select
            className={selectClass}
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={emptyForLocation}
          >
            <option value="">
              {emptyForLocation ? "— none configured —" : "Select…"}
            </option>
            {namesForLocation.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>

        <label className="form-control min-w-[8rem]">
          <span className="label-text text-xs">Role (optional)</span>
          <input
            className={inputClass}
            placeholder="name or UUID"
            value={role}
            onChange={(e) => setRole(e.target.value)}
          />
        </label>

        <button
          type="button"
          className="btn btn-xs btn-primary"
          disabled={!name || bind.running}
          onClick={async () => {
            try {
              await bind.run();
              setName("");
              setRole("");
              setConfigJson("");
              onDone();
            } catch {
              /* useAction logs */
            }
          }}
        >
          {bind.running ? (
            <span className="loading loading-spinner loading-xs" />
          ) : (
            "Bind"
          )}
        </button>
      </div>

      {emptyForLocation && (
        <div className="alert alert-warning text-xs py-2 mb-2">
          No {location} names in auth_config. Configure them on the{" "}
          <Link className="link" to="/auth">
            Auth page
          </Link>{" "}
          first (e.g. Authorization header).
        </div>
      )}

      <button
        type="button"
        className="btn btn-ghost btn-xs"
        onClick={() => setShowAdvanced((v) => !v)}
      >
        {showAdvanced ? "Hide" : "Show"} advanced config_json
      </button>
      {showAdvanced && (
        <div className="mt-2">
          <FieldHint text="Optional raw JSON for suite overrides (disabled_tests, claim_elevation, …). Leave empty unless you need binding-level config." />
          <textarea
            className="textarea textarea-bordered textarea-xs w-full font-mono mt-1"
            rows={3}
            placeholder='{"disabled_tests":[]}'
            value={configJson}
            onChange={(e) => setConfigJson(e.target.value)}
          />
        </div>
      )}
    </Section>
  );
}
