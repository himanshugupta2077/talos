"""
Module: talos.error_intel.detectors.stack_trace

Purpose:
    Stage A — language-family exception / stack-trace detectors.

    Highest-value Error Intelligence stage.  Emits RawErrorMatch with
    family=stack_trace, best-effort exception_type, and frame metadata.

    Families (v1):
        Java/JVM, .NET, Python, Node/JS, PHP, Ruby, Go, Rust

Dependencies: re; talos.error_intel.{constants, detectors.base, models}
Data flow: text → list[RawErrorMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

from talos.error_intel.constants import (
    CATEGORY_STACK_TRACE,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    DETECTOR_FAMILY_STACK,
    LANG_CSHARP,
    LANG_GO,
    LANG_JAVA,
    LANG_JAVASCRIPT,
    LANG_PHP,
    LANG_PYTHON,
    LANG_RUBY,
    LANG_RUST,
)
from talos.error_intel.detectors.base import (
    DEFAULT_STAGE_MATCH_CAP,
    build_raw_error_match,
    normalize_exception_type,
)
from talos.error_intel.models import RawErrorMatch

# ---------------------------------------------------------------------------
# Java / JVM
# ---------------------------------------------------------------------------

# Exception class line: java.sql.SQLSyntaxErrorException: message
# Also: Exception in thread "main" java.lang.NullPointerException
_JAVA_EXCEPTION = re.compile(
    r"(?:"
    r"Exception in thread\s+\"[^\"]+\"\s+)?"
    r"("
    r"(?:java|javax|jakarta|org\.hibernate|org\.springframework|"
    r"org\.apache|com\.mysql|oracle\.jdbc|io\.netty)"
    r"(?:\.[A-Za-z_][\w$]*)+"
    r"(?:Exception|Error|Throwable|Fault)"
    r"|"
    r"(?:SQLException|SQLSyntaxErrorException|SQLIntegrityConstraintViolationException|"
    r"HibernateException|PersistenceException|DataAccessException|"
    r"NullPointerException|IllegalArgumentException|ClassNotFoundException|"
    r"NoClassDefFoundError|ServletException|NestedServletException)"
    r")"
    r"(?:\s*:\s*[^\n\r]*)?",
    re.MULTILINE,
)

# Stack frame: at com.example.UserService.load(UserService.java:142)
_JAVA_FRAME = re.compile(
    r"^\s*at\s+"
    r"((?:[A-Za-z_][\w$]*\.)+[A-Za-z_<>$][\w$<>]*)"
    r"\(([^)]+)\)",
    re.MULTILINE,
)

_JAVA_CAUSED_BY = re.compile(
    r"^Caused by:\s*"
    r"((?:[A-Za-z_][\w.$]*)+)"
    r"(?:\s*:\s*([^\n\r]*))?",
    re.MULTILINE,
)

_JAVA_TECH_HINTS = (
    (re.compile(r"\borg\.hibernate\b", re.I), "hibernate"),
    (re.compile(r"\borg\.springframework\b", re.I), "spring"),
    (re.compile(r"\borg\.apache\.catalina\b|\bTomcat\b", re.I), "tomcat"),
    (re.compile(r"\borg\.eclipse\.jetty\b", re.I), "jetty"),
    (re.compile(r"\bcom\.mysql\b|\bmysql-connector\b", re.I), "mysql"),
    (re.compile(r"\borg\.postgresql\b", re.I), "postgresql"),
)

# ---------------------------------------------------------------------------
# .NET / C#
# ---------------------------------------------------------------------------

_DOTNET_EXCEPTION = re.compile(
    r"("
    r"System\.(?:[A-Za-z_][\w]*)*(?:Exception|Error)"
    r"|Microsoft\.(?:[A-Za-z_][\w.]*)*(?:Exception|Error)"
    r"|NullReferenceException|ArgumentNullException|InvalidOperationException|"
    r"HttpException|SqlException|DbException|TimeoutException"
    r")"
    r"(?:\s*:\s*[^\n\r]*)?",
)

# at Namespace.Type.Method(file.cs:line)
_DOTNET_FRAME = re.compile(
    r"^\s*at\s+"
    r"((?:[A-Za-z_][\w]*\.)+[A-Za-z_][\w`.]*)"
    r"(?:\s+in\s+[^\n]+)?",
    re.MULTILINE,
)

_STACKTRACE_LABEL = re.compile(r"\bStackTrace\s*:", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_PYTHON_TRACEBACK_HDR = re.compile(
    r"Traceback \(most recent call last\):",
)

_PYTHON_FILE_FRAME = re.compile(
    r'^\s*File\s+"([^"]+)",\s+line\s+(\d+)(?:,\s+in\s+(\S+))?',
    re.MULTILINE,
)

# Final exception line: ValueError: bad / django.core.exceptions.ValidationError: …
_PYTHON_EXCEPTION_LINE = re.compile(
    r"^((?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*(?:Error|Exception|Warning|Interrupt))"
    r"(?:\s*:\s*([^\n\r]*))?$",
    re.MULTILINE,
)

_PYTHON_TECH_HINTS = (
    (re.compile(r"\bdjango\b", re.I), "django"),
    (re.compile(r"\bflask\b|\bwerkzeug\b", re.I), "flask"),
    (re.compile(r"\bfastapi\b|\bstarlette\b", re.I), "fastapi"),
    (re.compile(r"\bsqlalchemy\b", re.I), "sqlalchemy"),
    (re.compile(r"\bpsycopg\b", re.I), "postgresql"),
)

# ---------------------------------------------------------------------------
# Node / JavaScript
# ---------------------------------------------------------------------------

_JS_EXCEPTION = re.compile(
    r"\b("
    r"TypeError|ReferenceError|SyntaxError|RangeError|URIError|EvalError|"
    r"UnhandledPromiseRejection(?:Warning)?|"
    r"Error"
    r")\s*:\s*([^\n\r]+)",
)

_JS_FRAME = re.compile(
    r"^\s*at\s+"
    r"(?:"
    r"(?:async\s+)?"
    r"([A-Za-z_$][\w.$]*)\s+\(([^)]+)\)"  # at Object.foo (/app/x.js:1:2)
    r"|"
    r"([^\s(]+\.(?:js|ts|mjs|cjs):\d+:\d+)"  # at /app/x.js:1:2
    r")",
    re.MULTILINE,
)

_JS_TECH_HINTS = (
    (re.compile(r"\bexpress\b|/node_modules/express/", re.I), "express"),
    (re.compile(r"\bnext(?:\.js)?\b|/node_modules/next/", re.I), "nextjs"),
    (re.compile(r"\bnode:internal\b", re.I), "nodejs"),
)

# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------

_PHP_FATAL = re.compile(
    r"\b((?:PHP\s+)?(?:Fatal error|Parse error|Warning|Notice|Deprecated))\s*:\s*"
    r"([^\n\r]+)",
    re.IGNORECASE,
)

_PHP_EXCEPTION = re.compile(
    r"\b((?:[A-Za-z_][\w]*\\)*[A-Za-z_][\w]*(?:Exception|Error))\b"
    r"(?:\s*:\s*([^\n\r]+))?",
)

_PHP_STACK_FRAME = re.compile(
    r"#\d+\s+([^\n\r]+)",
)

_PHP_TECH_HINTS = (
    (re.compile(r"\bLaravel\b|Illuminate\\", re.I), "laravel"),
    (re.compile(r"\bSymfony\b", re.I), "symfony"),
    (re.compile(r"\bYii\b", re.I), "yii"),
)

# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------

_RUBY_EXCEPTION = re.compile(
    r"\b("
    r"NoMethodError|NameError|ArgumentError|RuntimeError|LoadError|"
    r"ActiveRecord::[A-Za-z]+|ActionController::[A-Za-z]+|"
    r"ActionView::[A-Za-z]+"
    r")\s*(?:\([^\)]*\))?\s*:\s*([^\n\r]+)",
)

_RUBY_FRAME = re.compile(
    r"^\s*from\s+([^\n\r]+):\d+(?::in\s+`.+?`)?",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

_GO_PANIC = re.compile(
    r"\bpanic:\s*([^\n\r]+)",
)

_GO_GOROUTINE = re.compile(
    r"goroutine\s+\d+\s+\[[^\]]+\]:",
)

_GO_FRAME = re.compile(
    r"^((?:[A-Za-z0-9_./\-]+)\.[A-Za-z0-9_]+)\([^)]*\)\n\s+([^\n]+:\d+)",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

_RUST_PANIC = re.compile(
    r"thread\s+'([^']+)'\s+panicked\s+at(?:\s+'([^']*)')?",
    re.IGNORECASE,
)


class StackTraceDetector:
    """
    Purpose:
        Stage A orchestrator for language stack / exception patterns.
    """

    def __init__(self, *, max_matches: int = DEFAULT_STAGE_MATCH_CAP) -> None:
        self._max = max(1, int(max_matches))

    def detect(
        self,
        text: str,
        *,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        content_type: Optional[str] = None,
    ) -> list[RawErrorMatch]:
        """
        Purpose:
            Detect language-family stack traces / exceptions in text.
        Output:
            list[RawErrorMatch] family=stack_trace (capped).
        Side effects: None.
        """
        del status_code, headers, content_type  # stage A is body-driven
        if not text or not text.strip():
            return []

        matches: list[RawErrorMatch] = []
        # Order: high-specificity multi-line families first
        for finder in (
            self._detect_python,
            self._detect_java,
            self._detect_dotnet,
            self._detect_go,
            self._detect_rust,
            self._detect_php,
            self._detect_ruby,
            self._detect_javascript,
        ):
            if len(matches) >= self._max:
                break
            for m in finder(text):
                matches.append(m)
                if len(matches) >= self._max:
                    break
        return matches

    # --- family finders ---------------------------------------------------

    def _detect_java(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        seen_types: set[str] = set()

        for m in _JAVA_EXCEPTION.finditer(text):
            exc = normalize_exception_type(m.group(1))
            if not exc or exc.lower() in seen_types:
                continue
            seen_types.add(exc.lower())

            frames = _collect_java_frames(text, m.start())
            caused = _collect_caused_by(text)
            techs = _tech_tags(text, _JAVA_TECH_HINTS)
            conf = (
                CONFIDENCE_CONFIRMED_PATTERN
                if frames or "Caused by:" in text[m.start() : m.start() + 2000]
                else CONFIDENCE_HIGH
            )
            # Expand span to cover a few frames when present
            end = m.end()
            if frames:
                end = max(end, frames[-1].get("end", end))
            out.append(
                build_raw_error_match(
                    detector_id="stack_java",
                    family=DETECTOR_FAMILY_STACK,
                    text=text,
                    match_start=m.start(),
                    match_end=end,
                    exception_type=exc,
                    confidence=conf,
                    category_hint=CATEGORY_STACK_TRACE,
                    language=LANG_JAVA,
                    metadata={
                        "frames": frames[:12],
                        "caused_by": caused[:6],
                        "technologies": techs,
                        "has_stack_trace": bool(frames) or "at " in text[m.start() : m.start() + 800],
                    },
                )
            )
            if len(out) >= 3:
                break

        # Frames-only fallback (rare bare stack without exception line)
        if not out and _JAVA_FRAME.search(text) and (
            "Caused by:" in text or re.search(r"\bjava\.(?:lang|sql)\.", text)
        ):
            fm = _JAVA_FRAME.search(text)
            assert fm is not None
            frames = _collect_java_frames(text, 0)
            out.append(
                build_raw_error_match(
                    detector_id="stack_java_frames",
                    family=DETECTOR_FAMILY_STACK,
                    text=text,
                    match_start=fm.start(),
                    match_end=fm.end(),
                    exception_type=None,
                    confidence=CONFIDENCE_MEDIUM,
                    category_hint=CATEGORY_STACK_TRACE,
                    language=LANG_JAVA,
                    metadata={
                        "frames": frames[:12],
                        "technologies": _tech_tags(text, _JAVA_TECH_HINTS),
                        "has_stack_trace": True,
                    },
                )
            )
        return out

    def _detect_dotnet(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        seen: set[str] = set()
        for m in _DOTNET_EXCEPTION.finditer(text):
            exc = normalize_exception_type(m.group(1))
            if not exc or exc.lower() in seen:
                continue
            # Avoid Java-ish false positives: System. is strong for .NET
            if not exc.startswith("System.") and not exc.startswith("Microsoft."):
                if exc not in (
                    "NullReferenceException",
                    "ArgumentNullException",
                    "InvalidOperationException",
                    "HttpException",
                    "SqlException",
                    "DbException",
                    "TimeoutException",
                ):
                    continue
            seen.add(exc.lower())
            frames = []
            for fm in _DOTNET_FRAME.finditer(text):
                frames.append(
                    {
                        "method": fm.group(1),
                        "start": fm.start(),
                        "end": fm.end(),
                    }
                )
                if len(frames) >= 12:
                    break
            has_label = bool(_STACKTRACE_LABEL.search(text))
            conf = (
                CONFIDENCE_CONFIRMED_PATTERN
                if frames or has_label or exc.startswith("System.")
                else CONFIDENCE_HIGH
            )
            out.append(
                build_raw_error_match(
                    detector_id="stack_dotnet",
                    family=DETECTOR_FAMILY_STACK,
                    text=text,
                    match_start=m.start(),
                    match_end=m.end(),
                    exception_type=exc if exc.startswith("System.") or exc.startswith("Microsoft.") else f"System.{exc}" if "." not in exc else exc,
                    confidence=conf,
                    category_hint=CATEGORY_STACK_TRACE,
                    language=LANG_CSHARP,
                    metadata={
                        "frames": frames,
                        "has_stack_trace": bool(frames) or has_label,
                        "technologies": ["aspnet"] if re.search(r"ASP\.NET|HttpException", text, re.I) else [],
                    },
                )
            )
            if len(out) >= 3:
                break
        return out

    def _detect_python(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        hdr = _PYTHON_TRACEBACK_HDR.search(text)
        if not hdr:
            # Single-line exception without full traceback (weaker)
            for m in _PYTHON_EXCEPTION_LINE.finditer(text):
                name = m.group(1)
                # Require dotted module or well-known builtins in error pages
                if "." not in name and name not in _PYTHON_BUILTIN_EXC:
                    continue
                # Skip if looks like Java (java.lang.Exception)
                if name.startswith("java.") or name.startswith("javax."):
                    continue
                out.append(
                    build_raw_error_match(
                        detector_id="stack_python_exception",
                        family=DETECTOR_FAMILY_STACK,
                        text=text,
                        match_start=m.start(),
                        match_end=m.end(),
                        exception_type=normalize_exception_type(name),
                        confidence=CONFIDENCE_MEDIUM,
                        category_hint=CATEGORY_STACK_TRACE,
                        language=LANG_PYTHON,
                        metadata={
                            "message": (m.group(2) or "").strip()[:500],
                            "has_stack_trace": False,
                            "technologies": _tech_tags(text, _PYTHON_TECH_HINTS),
                        },
                    )
                )
                break
            return out

        # Full traceback block
        frames = []
        for fm in _PYTHON_FILE_FRAME.finditer(text, hdr.start()):
            frames.append(
                {
                    "file": fm.group(1),
                    "line": fm.group(2),
                    "function": fm.group(3),
                    "start": fm.start(),
                    "end": fm.end(),
                }
            )
            if len(frames) >= 20:
                break

        exc_type = None
        exc_msg = ""
        exc_start = hdr.start()
        exc_end = hdr.end()
        # Exception line usually follows frames
        search_from = frames[-1]["end"] if frames else hdr.end()
        for em in _PYTHON_EXCEPTION_LINE.finditer(text, search_from):
            # Prefer first after last frame; skip nested "Error" mid-stack
            candidate = em.group(1)
            if candidate.startswith("java.") or candidate.startswith("javax."):
                continue
            exc_type = normalize_exception_type(candidate)
            exc_msg = (em.group(2) or "").strip()[:500]
            exc_start = hdr.start()
            exc_end = em.end()
            break

        out.append(
            build_raw_error_match(
                detector_id="stack_python",
                family=DETECTOR_FAMILY_STACK,
                text=text,
                match_start=exc_start,
                match_end=exc_end,
                exception_type=exc_type,
                confidence=CONFIDENCE_CONFIRMED_PATTERN,
                category_hint=CATEGORY_STACK_TRACE,
                language=LANG_PYTHON,
                metadata={
                    "frames": frames[:12],
                    "message": exc_msg,
                    "has_stack_trace": True,
                    "technologies": _tech_tags(text, _PYTHON_TECH_HINTS),
                },
            )
        )
        return out

    def _detect_javascript(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        frames = []
        for fm in _JS_FRAME.finditer(text):
            method = fm.group(1) or None
            loc = fm.group(2) or fm.group(3) or ""
            frames.append({"method": method, "location": loc, "start": fm.start(), "end": fm.end()})
            if len(frames) >= 12:
                break

        seen: set[str] = set()
        for m in _JS_EXCEPTION.finditer(text):
            name = m.group(1)
            # Bare "Error:" is weak unless frames or UnhandledPromise present
            if name == "Error" and not frames and "UnhandledPromise" not in m.group(0):
                # Still allow if stack-looking "at " nearby
                window = text[max(0, m.start() - 20) : m.end() + 400]
                if not _JS_FRAME.search(window) and "at " not in window:
                    continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            msg = (m.group(2) or "").strip()[:500]
            conf = (
                CONFIDENCE_CONFIRMED_PATTERN
                if frames or name == "UnhandledPromiseRejection" or name.startswith("Unhandled")
                else CONFIDENCE_HIGH if name != "Error" else CONFIDENCE_MEDIUM
            )
            out.append(
                build_raw_error_match(
                    detector_id="stack_javascript",
                    family=DETECTOR_FAMILY_STACK,
                    text=text,
                    match_start=m.start(),
                    match_end=m.end(),
                    exception_type=normalize_exception_type(name),
                    confidence=conf,
                    category_hint=CATEGORY_STACK_TRACE,
                    language=LANG_JAVASCRIPT,
                    metadata={
                        "message": msg,
                        "frames": frames,
                        "has_stack_trace": bool(frames),
                        "technologies": _tech_tags(text, _JS_TECH_HINTS),
                    },
                )
            )
            if len(out) >= 3:
                break

        # Frames-only Node stack without Error: line
        if not out and frames and re.search(r"node_modules|node:internal", text):
            fm0 = frames[0]
            out.append(
                build_raw_error_match(
                    detector_id="stack_javascript_frames",
                    family=DETECTOR_FAMILY_STACK,
                    text=text,
                    match_start=int(fm0["start"]),
                    match_end=int(fm0["end"]),
                    exception_type=None,
                    confidence=CONFIDENCE_MEDIUM,
                    category_hint=CATEGORY_STACK_TRACE,
                    language=LANG_JAVASCRIPT,
                    metadata={
                        "frames": frames,
                        "has_stack_trace": True,
                        "technologies": _tech_tags(text, _JS_TECH_HINTS),
                    },
                )
            )
        return out

    def _detect_php(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        for m in _PHP_FATAL.finditer(text):
            kind = (m.group(1) or "").strip()
            msg = (m.group(2) or "").strip()[:500]
            # Extract "Call to undefined function foo()" style type
            exc = None
            undef = re.search(r"Call to undefined (?:function|method)\s+(\S+)", msg, re.I)
            if undef:
                exc = f"Undefined:{undef.group(1).rstrip('()')}"
            conf = (
                CONFIDENCE_CONFIRMED_PATTERN
                if re.search(r"Fatal error|Parse error", kind, re.I)
                else CONFIDENCE_HIGH
            )
            out.append(
                build_raw_error_match(
                    detector_id="stack_php",
                    family=DETECTOR_FAMILY_STACK,
                    text=text,
                    match_start=m.start(),
                    match_end=m.end(),
                    exception_type=normalize_exception_type(exc or kind),
                    confidence=conf,
                    category_hint=CATEGORY_STACK_TRACE,
                    language=LANG_PHP,
                    metadata={
                        "message": msg,
                        "php_level": kind,
                        "has_stack_trace": bool(_PHP_STACK_FRAME.search(text)),
                        "technologies": _tech_tags(text, _PHP_TECH_HINTS),
                    },
                )
            )
            if len(out) >= 2:
                break

        if not out:
            for m in _PHP_EXCEPTION.finditer(text):
                name = m.group(1)
                # Require backslash namespace or *Exception/*Error suffix in PHP style
                if "\\" not in name and not name.endswith(("Exception", "Error")):
                    continue
                # Skip pure Java/Python noise
                if name.startswith("java.") or name.startswith("System."):
                    continue
                out.append(
                    build_raw_error_match(
                        detector_id="stack_php_exception",
                        family=DETECTOR_FAMILY_STACK,
                        text=text,
                        match_start=m.start(),
                        match_end=m.end(),
                        exception_type=normalize_exception_type(name),
                        confidence=CONFIDENCE_HIGH if "\\" in name else CONFIDENCE_MEDIUM,
                        category_hint=CATEGORY_STACK_TRACE,
                        language=LANG_PHP,
                        metadata={
                            "message": (m.group(2) or "").strip()[:500],
                            "has_stack_trace": bool(_PHP_STACK_FRAME.search(text)),
                            "technologies": _tech_tags(text, _PHP_TECH_HINTS),
                        },
                    )
                )
                break
        return out

    def _detect_ruby(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        for m in _RUBY_EXCEPTION.finditer(text):
            name = normalize_exception_type(m.group(1))
            msg = (m.group(2) or "").strip()[:500]
            frames = []
            for fm in _RUBY_FRAME.finditer(text):
                frames.append({"location": fm.group(1), "start": fm.start(), "end": fm.end()})
                if len(frames) >= 12:
                    break
            techs = []
            if re.search(r"ActionController|ActionView|ActiveRecord|Rails", text, re.I):
                techs.append("rails")
            out.append(
                build_raw_error_match(
                    detector_id="stack_ruby",
                    family=DETECTOR_FAMILY_STACK,
                    text=text,
                    match_start=m.start(),
                    match_end=m.end(),
                    exception_type=name,
                    confidence=CONFIDENCE_CONFIRMED_PATTERN if frames else CONFIDENCE_HIGH,
                    category_hint=CATEGORY_STACK_TRACE,
                    language=LANG_RUBY,
                    metadata={
                        "message": msg,
                        "frames": frames,
                        "has_stack_trace": bool(frames),
                        "technologies": techs,
                    },
                )
            )
            break
        return out

    def _detect_go(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        panic = _GO_PANIC.search(text)
        goroutine = _GO_GOROUTINE.search(text)
        if not panic and not goroutine:
            return out
        msg = (panic.group(1).strip()[:500] if panic else "")
        start = panic.start() if panic else goroutine.start()  # type: ignore[union-attr]
        end = panic.end() if panic else goroutine.end()  # type: ignore[union-attr]
        frames = []
        for fm in _GO_FRAME.finditer(text):
            frames.append(
                {
                    "function": fm.group(1),
                    "location": fm.group(2),
                    "start": fm.start(),
                    "end": fm.end(),
                }
            )
            if len(frames) >= 12:
                break
        conf = CONFIDENCE_CONFIRMED_PATTERN if (panic and (goroutine or frames)) else CONFIDENCE_HIGH
        out.append(
            build_raw_error_match(
                detector_id="stack_go",
                family=DETECTOR_FAMILY_STACK,
                text=text,
                match_start=start,
                match_end=end,
                exception_type="panic" if panic else "goroutine",
                confidence=conf,
                category_hint=CATEGORY_STACK_TRACE,
                language=LANG_GO,
                metadata={
                    "message": msg,
                    "frames": frames,
                    "has_stack_trace": bool(frames) or bool(goroutine),
                    "technologies": ["go"],
                },
            )
        )
        return out

    def _detect_rust(self, text: str) -> list[RawErrorMatch]:
        out: list[RawErrorMatch] = []
        m = _RUST_PANIC.search(text)
        if not m:
            return out
        thread = m.group(1) or ""
        msg = (m.group(2) or "").strip()[:500]
        out.append(
            build_raw_error_match(
                detector_id="stack_rust",
                family=DETECTOR_FAMILY_STACK,
                text=text,
                match_start=m.start(),
                match_end=m.end(),
                exception_type="panic",
                confidence=CONFIDENCE_HIGH,
                category_hint=CATEGORY_STACK_TRACE,
                language=LANG_RUST,
                metadata={
                    "thread": thread,
                    "message": msg,
                    "has_stack_trace": "stack backtrace" in text.lower(),
                    "technologies": ["rust"],
                },
            )
        )
        return out


_PYTHON_BUILTIN_EXC = frozenset({
    "Exception",
    "BaseException",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "AttributeError",
    "RuntimeError",
    "OSError",
    "IOError",
    "NameError",
    "ImportError",
    "ModuleNotFoundError",
    "StopIteration",
    "AssertionError",
    "MemoryError",
    "RecursionError",
    "PermissionError",
    "FileNotFoundError",
    "ConnectionError",
    "TimeoutError",
    "UnicodeError",
    "UnicodeDecodeError",
    "ZeroDivisionError",
})


def _collect_java_frames(text: str, from_pos: int) -> list[dict]:
    frames: list[dict] = []
    # Search a window after the exception for frames
    window = text[from_pos : from_pos + 12_000]
    for fm in _JAVA_FRAME.finditer(window):
        frames.append(
            {
                "method": fm.group(1),
                "location": fm.group(2),
                "start": from_pos + fm.start(),
                "end": from_pos + fm.end(),
            }
        )
        if len(frames) >= 20:
            break
    return frames


def _collect_caused_by(text: str) -> list[dict]:
    out: list[dict] = []
    for m in _JAVA_CAUSED_BY.finditer(text):
        out.append(
            {
                "exception_type": normalize_exception_type(m.group(1)),
                "message": (m.group(2) or "").strip()[:300],
            }
        )
        if len(out) >= 8:
            break
    return out


def _tech_tags(text: str, rules: tuple) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    for pattern, tag in rules:
        if tag in seen:
            continue
        if pattern.search(text):
            seen.add(tag)
            tags.append(tag)
    return tags
