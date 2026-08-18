"""
Auth-config routes: per-role provider, login flows, extractors, session health,
validation control flows, and runtime recovery.

Mutations go through Talos CLI (`auth-config *`). Read snapshots use project
SQLite so the Auth workspace can render structured state without re-parsing CLI
tables.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(prefix="/api/auth-config", tags=["auth-config"])

# Mirrors talos.projects.session_health._SUSPICION_THRESHOLD (Layer 2).
_SUSPICION_THRESHOLD = 3


def _parse_json_field(raw, default):
    if raw is None or raw == "":
        return default
    if isinstance(raw, (list, dict)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _parse_dt(value: str | None) -> datetime | None:
    """
    Parse Talos session timestamps. Accepts ISO-8601 and the common
    session-file form ``2026-07-03 13:00 UTC`` (same as core).
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    # Core: expires_at.replace("UTC", "+00:00")
    if s.endswith(" UTC"):
        s = s[:-4].rstrip() + "+00:00"
    else:
        s = s.replace(" UTC", "+00:00").replace("UTC", "+00:00")
    # Allow space before offset produced by naive replace.
    s = s.replace(" +00:00", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _manual_session_expiry(manual_session: dict | None) -> datetime | None:
    """Mirror talos.projects.auth_provider.get_manual_session_expiry."""
    if not manual_session:
        return None
    expires_at = manual_session.get("expires_at")
    if expires_at:
        dt = _parse_dt(str(expires_at))
        if dt is not None:
            return dt
    ttl = manual_session.get("ttl_seconds")
    created = manual_session.get("created_at")
    if ttl is not None and created:
        base = _parse_dt(str(created))
        if base is not None:
            try:
                return base + timedelta(seconds=int(ttl))
            except (TypeError, ValueError):
                return None
    return None


def _normalize_manual_session(row: dict | None) -> dict | None:
    """DB row → structured manual session for the UI (parsed headers/cookies)."""
    if not row:
        return None
    headers = _parse_json_field(row.get("headers_json"), {})
    cookies = _parse_json_field(row.get("cookies_json"), {})
    expiry = _manual_session_expiry(row)
    remaining = None
    if expiry is not None:
        remaining = int((expiry - datetime.now(timezone.utc)).total_seconds())
    return {
        "headers": headers if isinstance(headers, dict) else {},
        "cookies": cookies if isinstance(cookies, dict) else {},
        "expires_at": row.get("expires_at"),
        "ttl_seconds": row.get("ttl_seconds"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "expires_in_seconds": remaining,
        "expiry_iso": expiry.isoformat() if expiry else None,
    }


def _session_display_state(
    provider: str | None,
    manual_session: dict | None,
    health: dict | None,
    artifacts: list[dict],
) -> str:
    """
    Mirror talos.projects.auth_provider.get_session_display_state using the
    already-loaded state snapshot (read-only; no Talos import).
    """
    if provider == "manual":
        # Core derives MANUAL display state from manual_session_config only
        # (not role_auth_state). Match that so Runtime reflects applied config.
        if not manual_session:
            return "WAITING_FOR_USER"
        expiry = _manual_session_expiry(manual_session)
        if expiry is None:
            return "WAITING_FOR_USER"
        remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            return "EXPIRED"
        if remaining < 300:
            return "EXPIRING"
        return "READY"

    # AUTO (or unset provider): age of collected role_auth_state vs TTL.
    if not artifacts:
        return "WAITING_FOR_USER"
    collected = next(
        (a.get("collected_at") for a in artifacts if a.get("collected_at")),
        None,
    )
    if not collected:
        return "WAITING_FOR_USER"
    collected_at = _parse_dt(str(collected))
    if collected_at is None:
        return "WAITING_FOR_USER"

    ttl = int((health or {}).get("ttl_seconds") or 1200)
    refresh_before = int((health or {}).get("refresh_before_seconds") or 120)
    age = (datetime.now(timezone.utc) - collected_at).total_seconds()
    if age >= ttl:
        return "EXPIRED"
    if age >= ttl - refresh_before:
        return "EXPIRING"
    return "READY"


def _format_session_file(
    headers: dict[str, str],
    cookies: dict[str, str],
    expires_at: str | None,
    ttl_seconds: int | None,
    role_label: str = "role",
) -> str:
    """
    Build the Talos manual session file format (same layout as
    format_session_template / parse_session_file).
    """
    lines = [
        f"# Manual session configuration for role: {role_label}",
        "# Lines starting with # are comments and are ignored.",
        "# Generated by Talos Control Panel structured session editor.",
        "",
    ]
    if headers:
        lines.append("--header")
        for name, value in headers.items():
            if not str(name).strip():
                continue
            lines.append(str(name).strip())
            lines.append(str(value))
            lines.append("")
    else:
        lines += ["--header", "# HeaderName", "# value", ""]

    if cookies:
        lines.append("--cookie")
        for name, value in cookies.items():
            if not str(name).strip():
                continue
            lines.append(str(name).strip())
            lines.append(str(value))
            lines.append("")
    else:
        lines += ["--cookie", "# cookie_name", "# value", ""]

    if expires_at and str(expires_at).strip():
        lines += ["expires_at", str(expires_at).strip(), ""]
    if ttl_seconds is not None:
        lines += ["ttl_seconds", str(int(ttl_seconds)), ""]
    if (not expires_at or not str(expires_at).strip()) and ttl_seconds is None:
        lines += [
            "# Provide either expires_at or ttl_seconds (required).",
            "# expires_at",
            "# 2026-07-15 18:00 UTC",
            "# ttl_seconds",
            "# 3600",
            "",
        ]
    return "\n".join(lines)


def _normalize_health(row: dict | None) -> dict:
    """Parse session_health_config JSON columns into structured values."""
    if not row:
        return {
            "ttl_seconds": 1200,
            "refresh_before_seconds": 120,
            "expiry_body_signals": [],
            "expiry_status_codes": [],
            "expiry_header_signals": {},
            "validation_endpoint_url": None,
            "validation_expected_status": 200,
            "has_row": False,
        }
    return {
        "ttl_seconds": row.get("ttl_seconds") if row.get("ttl_seconds") is not None else 1200,
        "refresh_before_seconds": (
            row.get("refresh_before_seconds")
            if row.get("refresh_before_seconds") is not None
            else 120
        ),
        "expiry_body_signals": _parse_json_field(row.get("expiry_body_signals"), []),
        "expiry_status_codes": _parse_json_field(row.get("expiry_status_codes"), []),
        "expiry_header_signals": _parse_json_field(row.get("expiry_header_signals"), {}),
        "validation_endpoint_url": row.get("validation_endpoint_url"),
        "validation_expected_status": row.get("validation_expected_status") or 200,
        "has_row": True,
    }


@router.get("/ntlm")
def list_ntlm_bindings(project_id: str):
    """Role → NTLM profile bindings plus the project auth model."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    try:
        from talos.projects.auth_mode import auth_mode_public_dict
        from talos.projects.role_ntlm import list_role_ntlm_bindings

        return {
            "auth": auth_mode_public_dict(db_path),
            "bindings": list_role_ntlm_bindings(db_path),
        }
    except Exception as exc:
        raise HTTPException(500, f"Failed to load NTLM bindings: {exc}") from exc


class BindNtlmBody(BaseModel):
    profile: str


@router.post("/{role_id}/ntlm")
def bind_ntlm(project_id: str, role_id: str, body: BindNtlmBody):
    results = cli.run_scoped(
        project_id, ["auth-config", "bind-ntlm", role_id, body.profile]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{role_id}/ntlm")
def unbind_ntlm(project_id: str, role_id: str):
    results = cli.run_scoped(project_id, ["auth-config", "unbind-ntlm", role_id])
    return {"steps": [r.to_dict() for r in results]}


@router.get("/{role_id}/state")
def role_auth_state(project_id: str, role_id: str):
    """
    Read-only snapshot for the Auth workspace: provider, artifacts, session,
    login flows (with flow metadata), health, control flows, suspicion.
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    provider = db.query_one(
        db_path, "SELECT provider, updated_at FROM role_auth_provider WHERE role_id=?", (role_id,)
    )
    artifacts = db.query_all(
        db_path, "SELECT key, value, collected_at FROM role_auth_state WHERE role_id=?", (role_id,)
    )
    manual_session = db.query_one(
        db_path,
        "SELECT headers_json, cookies_json, expires_at, ttl_seconds, "
        "created_at, updated_at "
        "FROM manual_session_config WHERE role_id=?",
        (role_id,),
    )
    flows = db.query_all(
        db_path,
        """
        SELECT afc.id, afc.flow_id,
               afc.extractor_code IS NOT NULL AS has_extractor,
               afc.sort_order,
               f.method, f.path, f.host, f.status_code, f.url
        FROM auth_flow_config afc
        LEFT JOIN flows f ON f.id = afc.flow_id
        WHERE afc.role_id = ?
        ORDER BY afc.sort_order
        """,
        (role_id,),
    )
    health_row = db.query_one(
        db_path,
        "SELECT ttl_seconds, refresh_before_seconds, expiry_body_signals, "
        "expiry_status_codes, expiry_header_signals, "
        "validation_endpoint_url, validation_expected_status "
        "FROM session_health_config WHERE role_id=?",
        (role_id,),
    )
    health = _normalize_health(health_row)
    control_flows = db.query_all(
        db_path,
        """
        SELECT shcf.flow_id, f.method, f.path, f.host, f.status_code, f.url
        FROM session_health_control_flows shcf
        LEFT JOIN flows f ON f.id = shcf.flow_id
        WHERE shcf.role_id = ?
        """,
        (role_id,),
    )
    suspicion = db.query_one(
        db_path,
        "SELECT suspicion_count, last_checked_at FROM session_suspicion_state WHERE role_id=?",
        (role_id,),
    )
    provider_name = (provider or {}).get("provider") if provider else None
    manual_structured = _normalize_manual_session(manual_session)
    session_state = _session_display_state(
        provider_name, manual_session, health, artifacts
    )

    # Age / expiry helpers for the runtime strip (display only; core owns TTL math).
    session_age_seconds = None
    expires_in_seconds = None
    collected_at = next((a.get("collected_at") for a in artifacts if a.get("collected_at")), None)
    if collected_at:
        ca = _parse_dt(str(collected_at))
        if ca is not None:
            session_age_seconds = int((datetime.now(timezone.utc) - ca).total_seconds())

    if provider_name == "manual":
        # MANUAL expiry always comes from manual_session_config (not health TTL).
        if manual_structured and manual_structured.get("expires_in_seconds") is not None:
            expires_in_seconds = manual_structured["expires_in_seconds"]
    elif collected_at and session_age_seconds is not None:
        expires_in_seconds = int(health["ttl_seconds"]) - session_age_seconds

    suspicion_count = (suspicion or {}).get("suspicion_count") or 0
    return {
        "provider": provider,
        "artifacts": artifacts,
        "manual_session": manual_structured,
        "flows": flows,
        "health": health,
        "control_flows": control_flows,
        "suspicion": suspicion,
        "session_state": session_state,
        "session_age_seconds": session_age_seconds,
        "expires_in_seconds": expires_in_seconds,
        "collected_at": collected_at,
        "suspicion_threshold": _SUSPICION_THRESHOLD,
        "health_degraded": suspicion_count >= _SUSPICION_THRESHOLD,
    }


class ProviderBody(BaseModel):
    provider: str  # auto | manual


@router.post("/{role_id}/provider")
def set_provider(project_id: str, role_id: str, body: ProviderBody):
    results = cli.run_scoped(project_id, ["auth-config", "set-provider", role_id, body.provider])
    return {"steps": [r.to_dict() for r in results]}


class ManualSessionFileBody(BaseModel):
    content: str


def _session_file_path(project_id: str, record: dict | None, role_id: str):
    """
    Mirrors talos.projects.model.Project.auth_session_path — the persistent
    per-role manual session file lives at <data_dir>/auth_sessions/<role_id>.txt.
    Kept in sync with that method; if it ever changes, update both places.
    """
    return config.project_data_dir(project_id, record) / "auth_sessions" / f"{role_id}.txt"


@router.get("/{role_id}/session/file")
def get_session_file(project_id: str, role_id: str):
    """
    Ensure the persistent manual-session file exists (creating it from a
    template via `talos auth-config set-session <role_id> path` if needed),
    then return its path and current contents so the UI can present an
    in-browser editor instead of requiring an external text editor.
    """
    path_result = cli.run_scoped(project_id, ["auth-config", "set-session", role_id, "path"])
    record = db.get_project_record(project_id)
    file_path = _session_file_path(project_id, record, role_id)
    content = file_path.read_text(encoding="utf-8") if file_path.exists() else ""
    return {
        "path": str(file_path),
        "content": content,
        "steps": [r.to_dict() for r in path_result],
    }


@router.post("/{role_id}/session/file")
def save_session_file(project_id: str, role_id: str, body: ManualSessionFileBody):
    """
    Write the operator-edited session file content directly to the same
    persistent path `talos auth-config set-session <role_id> path` created —
    functionally identical to editing it by hand in an external editor.
    """
    path_result = cli.run_scoped(project_id, ["auth-config", "set-session", role_id, "path"])
    record = db.get_project_record(project_id)
    file_path = _session_file_path(project_id, record, role_id)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(body.content, encoding="utf-8")
    return {"path": str(file_path), "steps": [r.to_dict() for r in path_result]}


@router.post("/{role_id}/session/apply")
def apply_session_file(project_id: str, role_id: str):
    """
    Parse the (already-edited) session file and apply it: checks provider is
    MANUAL and project-wide auth artifacts exist, then validates + refreshes.
    Mirrors `talos auth-config set-session <role_id>` (no path arg).
    """
    results = cli.run_scoped(project_id, ["auth-config", "set-session", role_id])
    return {"steps": [r.to_dict() for r in results]}


class ManualSessionStructuredBody(BaseModel):
    """Structured manual session — written as the Talos session file, then optional apply."""

    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    expires_at: str | None = None
    ttl_seconds: int | None = None
    apply: bool = False


@router.get("/{role_id}/session")
def get_session_structured(project_id: str, role_id: str):
    """
    Structured manual session for the Auth UI editor.
    Prefer applied DB config; fall back to parsing the session file.
    Ensures the session file path exists (set-session path) for file mode.
    """
    path_result = cli.run_scoped(project_id, ["auth-config", "set-session", role_id, "path"])
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    file_path = _session_file_path(project_id, record, role_id)
    file_content = file_path.read_text(encoding="utf-8") if file_path.exists() else ""

    row = db.query_one(
        db_path,
        "SELECT headers_json, cookies_json, expires_at, ttl_seconds, "
        "created_at, updated_at FROM manual_session_config WHERE role_id=?",
        (role_id,),
    )
    structured = _normalize_manual_session(row)
    if structured is None and file_content.strip():
        # Lazy parse of session-file format without importing Talos (mirror CLI).
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        expires_at = None
        ttl_seconds = None
        mode = None
        pending = None
        for raw in file_content.splitlines():
            line = raw.strip()
            if line == "--header":
                mode, pending = "header", None
                continue
            if line == "--cookie":
                mode, pending = "cookie", None
                continue
            if line == "expires_at":
                mode, pending = "expires", None
                continue
            if line == "ttl_seconds":
                mode, pending = "ttl", None
                continue
            if not line or line.startswith("#"):
                if not line:
                    pending = None
                continue
            if mode == "expires":
                expires_at = line
                mode = None
                continue
            if mode == "ttl":
                try:
                    ttl_seconds = int(line)
                except ValueError:
                    pass
                mode = None
                continue
            if mode in ("header", "cookie"):
                if pending is None:
                    pending = line
                else:
                    if mode == "header":
                        headers[pending] = line
                    else:
                        cookies[pending] = line
                    pending = None
        structured = {
            "headers": headers,
            "cookies": cookies,
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds,
            "created_at": None,
            "updated_at": None,
            "expires_in_seconds": None,
            "expiry_iso": None,
        }

    return {
        "path": str(file_path),
        "content": file_content,
        "session": structured
        or {
            "headers": {},
            "cookies": {},
            "expires_at": None,
            "ttl_seconds": None,
            "created_at": None,
            "updated_at": None,
            "expires_in_seconds": None,
            "expiry_iso": None,
        },
        "applied": row is not None,
        "steps": [r.to_dict() for r in path_result],
    }


@router.post("/{role_id}/session")
def save_session_structured(project_id: str, role_id: str, body: ManualSessionStructuredBody):
    """
    Write structured headers/cookies/expiry to the Talos session file.
    When apply=true, also runs `auth-config set-session <role>` (parse + apply + validate).
    """
    headers = {str(k).strip(): str(v) for k, v in (body.headers or {}).items() if str(k).strip()}
    cookies = {str(k).strip(): str(v) for k, v in (body.cookies or {}).items() if str(k).strip()}
    if not headers and not cookies:
        raise HTTPException(
            status_code=400,
            detail="Add at least one header or cookie with a name and value.",
        )
    if not (body.expires_at and str(body.expires_at).strip()) and body.ttl_seconds is None:
        raise HTTPException(
            status_code=400,
            detail="Provide expires_at (absolute UTC) or ttl_seconds (relative lifetime).",
        )

    path_result = cli.run_scoped(project_id, ["auth-config", "set-session", role_id, "path"])
    record = db.get_project_record(project_id)
    file_path = _session_file_path(project_id, record, role_id)
    # Role name for comment header (best-effort).
    role_row = db.query_one(
        config.project_db_path(project_id, record),
        "SELECT name FROM roles WHERE id=?",
        (role_id,),
    )
    role_label = (role_row or {}).get("name") or role_id
    content = _format_session_file(
        headers,
        cookies,
        body.expires_at,
        body.ttl_seconds,
        role_label=role_label,
    )
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")

    steps = [r.to_dict() for r in path_result]
    if body.apply:
        apply_results = cli.run_scoped(project_id, ["auth-config", "set-session", role_id])
        steps.extend(r.to_dict() for r in apply_results)
    return {"path": str(file_path), "content": content, "steps": steps}


@router.post("/{role_id}/session/clear")
def clear_session(project_id: str, role_id: str):
    """
    Clear manual session config — recovery from WAITING_FOR_USER / bad session.
    Mirrors `talos auth-config clear-session <role>`.
    """
    results = cli.run_scoped(project_id, ["auth-config", "clear-session", role_id])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{role_id}/flows/{flow_id}")
def add_flow(project_id: str, role_id: str, flow_id: str):
    results = cli.run_scoped(project_id, ["auth-config", "add-flow", role_id, flow_id])
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{role_id}/flows/{flow_id}")
def remove_flow(project_id: str, role_id: str, flow_id: str):
    results = cli.run_scoped(project_id, ["auth-config", "remove-flow", role_id, flow_id])
    return {"steps": [r.to_dict() for r in results]}


class ExtractorBody(BaseModel):
    code: str


@router.get("/{role_id}/flows/{flow_id}/extractor")
def get_extractor(project_id: str, role_id: str, flow_id: str):
    """
    Return extractor source for inspect/edit in the UI.
    Reads SQLite (same store as `talos auth-config show-extractor`).
    """
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    row = db.query_one(
        db_path,
        "SELECT extractor_code FROM auth_flow_config WHERE role_id=? AND flow_id=?",
        (role_id, flow_id),
    )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Login flow {flow_id} is not attached to this role.",
        )
    return {
        "flow_id": flow_id,
        "role_id": role_id,
        "code": row.get("extractor_code") or "",
        "configured": bool(row.get("extractor_code")),
    }


@router.post("/{role_id}/flows/{flow_id}/extractor")
def set_extractor(project_id: str, role_id: str, flow_id: str, body: ExtractorBody):
    results = cli.run_scoped_with_temp_file(
        project_id, ["auth-config", "set-extractor", role_id, flow_id], body.code, suffix=".py"
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{role_id}/flows/{flow_id}/extractor/edit")
def edit_extractor(project_id: str, role_id: str, flow_id: str, body: ExtractorBody):
    results = cli.run_scoped_with_editor_content(
        project_id, ["auth-config", "edit-extractor", role_id, flow_id], body.code
    )
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{role_id}/flows/{flow_id}/extractor")
def remove_extractor(project_id: str, role_id: str, flow_id: str):
    results = cli.run_scoped(project_id, ["auth-config", "remove-extractor", role_id, flow_id])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{role_id}/test/{flow_id}")
def test_flow(project_id: str, role_id: str, flow_id: str):
    """
    Test one login flow + extractor. Does not store auth state.
    Uses CLI JSON output so the UI can show full extracted token values.
    """
    results = cli.run_scoped(
        project_id, ["auth-config", "test", role_id, flow_id, "--format", "json"]
    )
    return {"steps": [r.to_dict() for r in results]}


class ValidateBody(BaseModel):
    """Optional single control-flow UUID to validate (Layer 3 probe)."""

    flow_id: str | None = None


@router.post("/{role_id}/validate")
def validate(project_id: str, role_id: str, body: ValidateBody | None = None):
    """
    Validate session. Optional body.flow_id limits Layer 3 probes to one
    control flow (`auth-config validate <role> --flow <id>`).
    """
    args = ["auth-config", "validate", role_id]
    flow_id = (body.flow_id if body else None) or None
    if flow_id:
        args += ["--flow", flow_id]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{role_id}/refresh")
def refresh(project_id: str, role_id: str):
    results = cli.run_scoped(project_id, ["auth-config", "refresh", role_id])
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{role_id}/reset-health")
def reset_health(project_id: str, role_id: str):
    """Reset Layer 2 suspicion counter — recovery from false expiry-signal storms."""
    results = cli.run_scoped(project_id, ["auth-config", "reset-health", role_id])
    return {"steps": [r.to_dict() for r in results]}


class TtlBody(BaseModel):
    ttl: int
    refresh_before: int | None = None


@router.post("/{role_id}/ttl")
def set_ttl(project_id: str, role_id: str, body: TtlBody):
    args = ["auth-config", "set-ttl", role_id, "--ttl", str(body.ttl)]
    if body.refresh_before is not None:
        args += ["--refresh-before", str(body.refresh_before)]
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


class HeaderSignal(BaseModel):
    name: str
    value: str


class ExpirySignalBody(BaseModel):
    body_signals: list[str] = []
    status_codes: list[int] = []
    header_signals: list[HeaderSignal] = []


@router.post("/{role_id}/expiry-signals")
def add_expiry_signal(project_id: str, role_id: str, body: ExpirySignalBody):
    args = ["auth-config", "add-expiry-signal", role_id]
    for b in body.body_signals:
        args += ["--body", b]
    for s in body.status_codes:
        args += ["--status", str(s)]
    for h in body.header_signals:
        args += ["--header", h.name, h.value]
    if len(args) == 3:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one body, status, or header expiry signal.",
        )
    results = cli.run_scoped(project_id, args)
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{role_id}/expiry-signals")
def clear_expiry_signals(project_id: str, role_id: str):
    # Core only supports clear-all; non-interactive requires --force.
    results = cli.run_scoped(
        project_id, ["auth-config", "clear-expiry-signals", role_id, "--force"]
    )
    return {"steps": [r.to_dict() for r in results]}


@router.post("/{role_id}/control-flows/{flow_id}")
def add_control_flow(project_id: str, role_id: str, flow_id: str):
    results = cli.run_scoped(project_id, ["auth-config", "add-control-flow", role_id, flow_id])
    return {"steps": [r.to_dict() for r in results]}


@router.delete("/{role_id}/control-flows/{flow_id}")
def remove_control_flow(project_id: str, role_id: str, flow_id: str):
    results = cli.run_scoped(project_id, ["auth-config", "remove-control-flow", role_id, flow_id])
    return {"steps": [r.to_dict() for r in results]}
