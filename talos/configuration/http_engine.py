"""
Module: talos.configuration.http_engine

Purpose:
    HTTP Manipulation Engine — single pipeline that applies declarative
    HTTP rules to outbound requests and inbound responses.

    Replaces:
        - HeaderMutationEngine (capture.header_rules)
        - DB request_mutations (talos mutation)

    Execution:
        1. Skip entirely when http.enabled is false.
        2. Consider rules sorted by priority (ascending).
        3. For each enabled rule matching direction + conditions, run
           its actions sequentially.
        4. Request-only / response-only ops are ignored on the wrong half.

Dependencies: logging, re, time, urllib.parse, talos.configuration.http_rules
Data flow:
    EffectiveConfig.http → HTTPManipulationEngine → mitmproxy flow mutation
Side effects:
    Mutates request/response headers, URL, method, body, status; may sleep
    (delay), kill flow (drop/abort).
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, MutableMapping, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from talos.configuration.http_rules import (
    REQUEST_ONLY_OPS,
    RESPONSE_ONLY_OPS,
    rule_matches,
)

logger = logging.getLogger(__name__)


class HTTPManipulationEngine:
    """
    Purpose:
        Stateless-ish engine: holds the effective rule list and master
        switch, applies them to request or response messages.

    Fields:
        enabled — master switch (http.enabled).
        rules   — effective sorted rule list (dicts).
    """

    def __init__(
        self,
        rules: Optional[list[dict[str, Any]]] = None,
        *,
        enabled: bool = True,
    ) -> None:
        self.enabled: bool = bool(enabled)
        self.rules: list[dict[str, Any]] = list(rules or [])

    @classmethod
    def from_http_section(cls, section: Any) -> "HTTPManipulationEngine":
        """
        Purpose:
            Build an engine from HttpConfigSection or duck-typed object
            with ``enabled`` and ``rules`` attributes.
        Side effects: None.
        """
        enabled = bool(getattr(section, "enabled", True))
        rules = list(getattr(section, "rules", None) or [])
        return cls(rules, enabled=enabled)

    # ------------------------------------------------------------------ #
    # Public apply                                                         #
    # ------------------------------------------------------------------ #

    def apply_request(
        self,
        *,
        method: str,
        url: str,
        headers: MutableMapping[str, str],
        get_body: Optional[Callable[[], Any]] = None,
        set_body: Optional[Callable[[Any], None]] = None,
        set_method: Optional[Callable[[str], None]] = None,
        set_url: Optional[Callable[[str], None]] = None,
        kill: Optional[Callable[[], None]] = None,
        host: str = "",
        path: str = "",
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Purpose:
            Evaluate request-direction rules and execute matching actions.
        Input:
            method/url/headers — current request fields.
            get_body/set_body  — optional body accessors (bytes|str).
            set_method/set_url — optional mutators.
            kill               — optional callable to drop the flow.
            host/path          — for matching (derived from url when empty).
            context            — Talos flags (replay, bac, role_id, …).
        Output:
            Stats dict: rules_matched, actions_run, dropped.
        Side effects:
            Mutates headers and optional request fields; may sleep or kill.
        """
        if not self.enabled:
            return {"rules_matched": 0, "actions_run": 0, "dropped": False}

        if not host or not path:
            parts = urlsplit(url)
            host = host or parts.hostname or ""
            path = path or parts.path or "/"

        matched = 0
        actions_run = 0
        body_cache: Optional[Any] = None

        for rule in self.rules:
            if not rule_matches(
                rule,
                direction="request",
                method=method,
                host=host,
                path=path,
                url=url,
                headers=headers,
                content_type=_header_get(headers, "Content-Type") or "",
                context=context,
            ):
                continue
            matched += 1
            for action in rule.get("actions") or []:
                op = str(action.get("op", ""))
                if op in RESPONSE_ONLY_OPS:
                    continue
                if op in ("drop", "abort"):
                    actions_run += 1
                    if kill is not None:
                        kill()
                    return {
                        "rules_matched": matched,
                        "actions_run": actions_run,
                        "dropped": True,
                    }
                if op == "delay":
                    ms = int(action.get("ms") or 0)
                    if ms > 0:
                        time.sleep(ms / 1000.0)
                    actions_run += 1
                    continue

                if op.startswith("body.") and get_body is not None and set_body is not None:
                    if body_cache is None:
                        body_cache = get_body()
                    body_cache = self._apply_body_action(action, body_cache)
                    set_body(body_cache)
                    actions_run += 1
                    continue

                if op == "method.replace" and set_method is not None:
                    set_method(str(action["value"]))
                    method = str(action["value"])
                    actions_run += 1
                    continue

                if op in ("url.host", "url.path") and set_url is not None:
                    url = self._apply_url_action(action, url)
                    set_url(url)
                    parts = urlsplit(url)
                    host = parts.hostname or host
                    path = parts.path or path
                    actions_run += 1
                    continue

                if op.startswith("query."):
                    url = self._apply_query_action(action, url)
                    if set_url is not None:
                        set_url(url)
                    actions_run += 1
                    continue

                if op.startswith("cookie."):
                    self._apply_cookie_request_action(action, headers)
                    actions_run += 1
                    continue

                if op.startswith("header."):
                    self._apply_header_action(action, headers)
                    actions_run += 1
                    continue

                logger.debug("Skipping unsupported request action op=%s", op)

        return {
            "rules_matched": matched,
            "actions_run": actions_run,
            "dropped": False,
        }

    def apply_response(
        self,
        *,
        method: str,
        url: str,
        status_code: int,
        headers: MutableMapping[str, str],
        get_body: Optional[Callable[[], Any]] = None,
        set_body: Optional[Callable[[Any], None]] = None,
        set_status: Optional[Callable[[int], None]] = None,
        kill: Optional[Callable[[], None]] = None,
        host: str = "",
        path: str = "",
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Purpose:
            Evaluate response-direction rules and execute matching actions.
        Output:
            Stats dict: rules_matched, actions_run, dropped.
        Side effects:
            Mutates response headers/body/status; may sleep or kill.
        """
        if not self.enabled:
            return {"rules_matched": 0, "actions_run": 0, "dropped": False}

        if not host or not path:
            parts = urlsplit(url)
            host = host or parts.hostname or ""
            path = path or parts.path or "/"

        matched = 0
        actions_run = 0
        body_cache: Optional[Any] = None

        for rule in self.rules:
            if not rule_matches(
                rule,
                direction="response",
                method=method,
                host=host,
                path=path,
                url=url,
                status_code=status_code,
                headers=headers,
                content_type=_header_get(headers, "Content-Type") or "",
                context=context,
            ):
                continue
            matched += 1
            for action in rule.get("actions") or []:
                op = str(action.get("op", ""))
                if op in REQUEST_ONLY_OPS:
                    continue
                if op in ("drop", "abort"):
                    actions_run += 1
                    if kill is not None:
                        kill()
                    return {
                        "rules_matched": matched,
                        "actions_run": actions_run,
                        "dropped": True,
                    }
                if op == "delay":
                    ms = int(action.get("ms") or 0)
                    if ms > 0:
                        time.sleep(ms / 1000.0)
                    actions_run += 1
                    continue
                if op == "status.override" and set_status is not None:
                    set_status(int(action["value"]))
                    status_code = int(action["value"])
                    actions_run += 1
                    continue
                if op.startswith("body.") and get_body is not None and set_body is not None:
                    if body_cache is None:
                        body_cache = get_body()
                    body_cache = self._apply_body_action(action, body_cache)
                    set_body(body_cache)
                    actions_run += 1
                    continue
                if op.startswith("cookie."):
                    self._apply_cookie_response_action(action, headers)
                    actions_run += 1
                    continue
                if op.startswith("header."):
                    self._apply_header_action(action, headers)
                    actions_run += 1
                    continue
                logger.debug("Skipping unsupported response action op=%s", op)

        return {
            "rules_matched": matched,
            "actions_run": actions_run,
            "dropped": False,
        }

    def apply_request_flow(self, flow: Any, *, context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """
        Purpose:
            Convenience: apply request rules to a mitmproxy HTTPFlow.
        Side effects: Mutates flow.request; may kill the flow.
        """
        req = flow.request

        def _get_body() -> bytes:
            return req.content or b""

        def _set_body(value: Any) -> None:
            if isinstance(value, str):
                req.content = value.encode("utf-8", errors="replace")
            else:
                req.content = bytes(value or b"")
            # Invalidate Content-Length so mitmproxy recalculates.
            if "Content-Length" in req.headers:
                req.headers["Content-Length"] = str(len(req.content or b""))

        def _set_method(value: str) -> None:
            req.method = value

        def _set_url(value: str) -> None:
            req.url = value

        def _kill() -> None:
            flow.kill()

        host = ""
        path = ""
        try:
            host = req.pretty_host or ""
        except Exception:
            host = getattr(req, "host", "") or ""
        try:
            path = urlsplit(req.pretty_url).path or "/"
        except Exception:
            path = getattr(req, "path", "/") or "/"

        url = ""
        try:
            url = req.pretty_url
        except Exception:
            url = getattr(req, "url", "") or ""

        return self.apply_request(
            method=str(req.method or "GET"),
            url=url,
            headers=req.headers,
            get_body=_get_body,
            set_body=_set_body,
            set_method=_set_method,
            set_url=_set_url,
            kill=_kill,
            host=host,
            path=path,
            context=context,
        )

    def apply_response_flow(self, flow: Any, *, context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """
        Purpose:
            Convenience: apply response rules to a mitmproxy HTTPFlow.
        Side effects: Mutates flow.response; may kill the flow.
        """
        req = flow.request
        resp = flow.response
        if resp is None:
            return {"rules_matched": 0, "actions_run": 0, "dropped": False}

        def _get_body() -> bytes:
            return resp.content or b""

        def _set_body(value: Any) -> None:
            if isinstance(value, str):
                resp.content = value.encode("utf-8", errors="replace")
            else:
                resp.content = bytes(value or b"")
            if "Content-Length" in resp.headers:
                resp.headers["Content-Length"] = str(len(resp.content or b""))

        def _set_status(code: int) -> None:
            resp.status_code = code

        def _kill() -> None:
            flow.kill()

        host = ""
        path = ""
        try:
            host = req.pretty_host or ""
        except Exception:
            host = getattr(req, "host", "") or ""
        try:
            path = urlsplit(req.pretty_url).path or "/"
        except Exception:
            path = getattr(req, "path", "/") or "/"
        url = ""
        try:
            url = req.pretty_url
        except Exception:
            url = getattr(req, "url", "") or ""

        return self.apply_response(
            method=str(req.method or "GET"),
            url=url,
            status_code=int(resp.status_code or 0),
            headers=resp.headers,
            get_body=_get_body,
            set_body=_set_body,
            set_status=_set_status,
            kill=_kill,
            host=host,
            path=path,
            context=context,
        )

    # ------------------------------------------------------------------ #
    # Action implementations                                               #
    # ------------------------------------------------------------------ #

    def _apply_header_action(
        self, action: dict[str, Any], headers: MutableMapping[str, str]
    ) -> None:
        op = action["op"]
        if op == "header.remove":
            _header_pop(headers, str(action["name"]))
        elif op == "header.replace":
            _header_pop(headers, str(action["name"]))
            headers[str(action["name"])] = str(action["value"])
        elif op == "header.add":
            if _header_get(headers, str(action["name"])) is None:
                headers[str(action["name"])] = str(action["value"])
        elif op == "header.rename":
            old = str(action["from"])
            new = str(action["to"])
            existing = _header_pop(headers, old)
            if existing is not None:
                headers[new] = existing

    def _apply_cookie_request_action(
        self, action: dict[str, Any], headers: MutableMapping[str, str]
    ) -> None:
        """
        Purpose: Mutate the request Cookie header.
        """
        raw = _header_get(headers, "Cookie") or ""
        cookies = _parse_cookie_header(raw)
        name = str(action["name"])
        op = action["op"]
        if op == "cookie.remove":
            cookies.pop(name, None)
        elif op == "cookie.replace":
            cookies[name] = str(action["value"])
        elif op == "cookie.add":
            if name not in cookies:
                cookies[name] = str(action["value"])
        new_val = _format_cookie_header(cookies)
        _header_pop(headers, "Cookie")
        if new_val:
            headers["Cookie"] = new_val

    def _apply_cookie_response_action(
        self, action: dict[str, Any], headers: MutableMapping[str, str]
    ) -> None:
        """
        Purpose:
            Mutate Set-Cookie headers. remove drops matching cookie name;
            replace/add sets a simple Set-Cookie name=value.
        """
        name = str(action["name"])
        op = action["op"]
        # Collect non-matching Set-Cookie values
        kept: list[str] = []
        # mitmproxy Headers may expose get_all; fall back to single value.
        existing_values: list[str] = []
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            try:
                existing_values = list(get_all("Set-Cookie") or [])
            except Exception:
                existing_values = []
        if not existing_values:
            single = _header_get(headers, "Set-Cookie")
            if single:
                existing_values = [single]

        # Remove all Set-Cookie keys then re-add kept / new.
        while _header_pop(headers, "Set-Cookie") is not None:
            pass

        for val in existing_values:
            cookie_name = val.split("=", 1)[0].strip()
            if cookie_name.lower() == name.lower():
                if op == "cookie.remove":
                    continue
                if op == "cookie.replace":
                    kept.append(f"{name}={action['value']}")
                    continue
            kept.append(val)

        if op == "cookie.add":
            if not any(v.split("=", 1)[0].strip().lower() == name.lower() for v in kept):
                kept.append(f"{name}={action['value']}")
        elif op == "cookie.replace" and not any(
            v.split("=", 1)[0].strip().lower() == name.lower() for v in kept
        ):
            kept.append(f"{name}={action['value']}")

        for val in kept:
            # Prefer add for multi-value headers when available.
            add = getattr(headers, "add", None)
            if callable(add):
                add("Set-Cookie", val)
            else:
                headers["Set-Cookie"] = val

    def _apply_query_action(self, action: dict[str, Any], url: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        name = str(action["name"])
        op = action["op"]
        if op == "query.remove":
            pairs = [(k, v) for k, v in pairs if k != name]
        elif op == "query.replace":
            found = False
            new_pairs = []
            for k, v in pairs:
                if k == name:
                    new_pairs.append((k, str(action["value"])))
                    found = True
                else:
                    new_pairs.append((k, v))
            if not found:
                new_pairs.append((name, str(action["value"])))
            pairs = new_pairs
        elif op == "query.add":
            if not any(k == name for k, _ in pairs):
                pairs.append((name, str(action["value"])))
        new_query = urlencode(pairs, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def _apply_url_action(self, action: dict[str, Any], url: str) -> str:
        parts = urlsplit(url)
        op = action["op"]
        value = str(action["value"])
        if op == "url.host":
            # Preserve port when value has no port and original had one.
            userinfo = ""
            netloc = parts.netloc
            if "@" in netloc:
                userinfo, netloc = netloc.rsplit("@", 1)
            # Rebuild netloc with new host, keep port if value omits it.
            if ":" in value and not value.startswith("["):
                new_hostport = value
            else:
                old_port = parts.port
                if old_port and ":" not in value:
                    new_hostport = f"{value}:{old_port}"
                else:
                    new_hostport = value
            if userinfo:
                new_netloc = f"{userinfo}@{new_hostport}"
            else:
                new_netloc = new_hostport
            return urlunsplit((parts.scheme, new_netloc, parts.path, parts.query, parts.fragment))
        if op == "url.path":
            return urlunsplit((parts.scheme, parts.netloc, value, parts.query, parts.fragment))
        return url

    def _apply_body_action(self, action: dict[str, Any], body: Any) -> Any:
        op = action["op"]
        is_bytes = isinstance(body, (bytes, bytearray))
        text = body.decode("utf-8", errors="replace") if is_bytes else str(body or "")
        if op == "body.append":
            text = text + str(action["value"])
        elif op == "body.prepend":
            text = str(action["value"]) + text
        elif op == "body.regex_replace":
            pattern = str(action["pattern"])
            replacement = str(action.get("replacement", ""))
            text = re.sub(pattern, replacement, text)
        if is_bytes:
            return text.encode("utf-8", errors="replace")
        return text


# ------------------------------------------------------------------ #
# Header / cookie helpers                                              #
# ------------------------------------------------------------------ #


def _header_get(headers: MutableMapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for key in list(headers.keys()):
        if str(key).lower() == target:
            return str(headers[key])
    return None


def _header_pop(headers: MutableMapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for key in list(headers.keys()):
        if str(key).lower() == target:
            try:
                return headers.pop(key)  # type: ignore[call-arg]
            except TypeError:
                value = headers[key]
                del headers[key]
                return str(value)
    return None


def _parse_cookie_header(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    if not raw:
        return result
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[part] = ""
    return result


def _format_cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())
