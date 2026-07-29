"""
Module: talos.error_intel.detectors.framework

Purpose:
    Stage C — framework / app-server error chrome detectors.

    Spring Boot Whitelabel, Laravel Whoops, Rails, ASP.NET YSOD,
    Django debug, Werkzeug, Express/Next, Tomcat/Jetty status pages, etc.

Dependencies: re; talos.error_intel.{constants, detectors.base, models}
Data flow: text → list[RawErrorMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

from talos.error_intel.constants import (
    CATEGORY_FRAMEWORK,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    DETECTOR_FAMILY_FRAMEWORK,
    LANG_CSHARP,
    LANG_JAVA,
    LANG_JAVASCRIPT,
    LANG_PHP,
    LANG_PYTHON,
    LANG_RUBY,
    LANG_UNKNOWN,
)
from talos.error_intel.detectors.base import (
    DEFAULT_STAGE_MATCH_CAP,
    build_raw_error_match,
)
from talos.error_intel.models import RawErrorMatch

# (detector_id, pattern, framework, language, confidence, exception_type_or_None)
_CHROME_RULES: tuple[tuple[str, re.Pattern[str], str, str, str, Optional[str]], ...] = (
    (
        "fw_spring_whitelabel",
        re.compile(r"Whitelabel Error Page", re.I),
        "spring",
        LANG_JAVA,
        CONFIDENCE_CONFIRMED_PATTERN,
        "WhitelabelErrorPage",
    ),
    (
        "fw_werkzeug",
        re.compile(r"Werkzeug Debugger|WORKZEUG|>>>\s*evalconsole", re.I),
        "werkzeug",
        LANG_PYTHON,
        CONFIDENCE_CONFIRMED_PATTERN,
        "WerkzeugDebugger",
    ),
    (
        "fw_django_debug",
        re.compile(
            r"Django (?:Version|Debug)|You're seeing this error because you have\s+`?DEBUG\s*=\s*True",
            re.I,
        ),
        "django",
        LANG_PYTHON,
        CONFIDENCE_CONFIRMED_PATTERN,
        "DjangoDebugPage",
    ),
    (
        "fw_laravel_whoops",
        # Require Whoops/Ignition chrome — bare "Laravel Framework" is marketing copy.
        re.compile(
            r"\bWhoops!\b|"
            r"Ignition\\|"
            r"/vendor/filp/whoops/|"
            r"\bWhoops\\\\|"
            r"facade/ignition|"
            r"spatie/laravel-ignition|"
            r"Laravel\s+Exception|"
            r"Illuminate\\(?:View|Foundation)\\.*Exception",
            re.I,
        ),
        "laravel",
        LANG_PHP,
        CONFIDENCE_HIGH,
        "Whoops",
    ),
    (
        "fw_rails",
        re.compile(
            r"Action Controller: Exception caught|Web application could not be started|"
            r"Rails\.root|ActionController::",
            re.I,
        ),
        "rails",
        LANG_RUBY,
        CONFIDENCE_HIGH,
        "ActionControllerException",
    ),
    (
        "fw_aspnet_ysod",
        re.compile(
            r"Server Error in '/[^']*'\s*Application|"
            r"ASP\.NET\s+(?:Error|Runtime)|"
            r"Yellow Screen of Death|"
            r"System\.Web\.HttpException",
            re.I,
        ),
        "aspnet",
        LANG_CSHARP,
        CONFIDENCE_HIGH,
        "AspNetServerError",
    ),
    (
        "fw_tomcat",
        re.compile(
            r"Apache Tomcat/(?:[\d.]+)|"
            r"HTTP Status \d{3}\s*[–—-]\s*.*"
            r"|type Status report|"
            r"message\s+.*\s+description\s+The server encountered",
            re.I,
        ),
        "tomcat",
        LANG_JAVA,
        CONFIDENCE_MEDIUM,
        "TomcatStatusPage",
    ),
    (
        "fw_jetty",
        re.compile(r"\bPowered by Jetty://|\bEclipse Jetty\b|org\.eclipse\.jetty\.", re.I),
        "jetty",
        LANG_JAVA,
        CONFIDENCE_MEDIUM,
        "JettyErrorPage",
    ),
    (
        "fw_express",
        re.compile(
            r"Cannot (?:GET|POST|PUT|PATCH|DELETE) /[^\n]*\n\s*at\s+Layer\.handle|"
            r"<pre>Cannot (?:GET|POST)|"
            r"Express\s+server error",
            re.I,
        ),
        "express",
        LANG_JAVASCRIPT,
        CONFIDENCE_MEDIUM,
        "ExpressError",
    ),
    (
        "fw_nextjs",
        re.compile(
            r"__NEXT_DATA__|__NEXT_ERROR__|next/dist/client|"
            r"Unhandled Runtime Error|"
            r"Next\.js\s+\([\d.]+\)",
            re.I,
        ),
        "nextjs",
        LANG_JAVASCRIPT,
        CONFIDENCE_MEDIUM,
        "NextJsError",
    ),
    (
        "fw_fastapi",
        re.compile(r"fastapi\.exceptions|starlette\.middleware\.errors", re.I),
        "fastapi",
        LANG_PYTHON,
        CONFIDENCE_MEDIUM,
        "FastAPIError",
    ),
    (
        "fw_symfony",
        re.compile(r"Symfony Exception|Symfony\\Component\\HttpKernel", re.I),
        "symfony",
        LANG_PHP,
        CONFIDENCE_HIGH,
        "SymfonyException",
    ),
    (
        "fw_yii",
        re.compile(r"Yii Framework|yii\\base\\ErrorException", re.I),
        "yii",
        LANG_PHP,
        CONFIDENCE_MEDIUM,
        "YiiError",
    ),
)


class FrameworkErrorDetector:
    """
    Purpose:
        Stage C — framework-branded error pages / handlers.
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
        del status_code, headers, content_type
        if not text or not text.strip():
            return []

        matches: list[RawErrorMatch] = []
        seen_fw: set[str] = set()

        for detector_id, pattern, framework, language, confidence, exc in _CHROME_RULES:
            if framework in seen_fw:
                continue
            # FastAPI rule is too loose with bare {"detail": — require more
            if detector_id == "fw_fastapi":
                if not re.search(
                    r"fastapi\.exceptions|starlette\.middleware\.errors|"
                    r"\"detail\"\s*:\s*\[|ValidationError",
                    text,
                    re.I,
                ):
                    continue
            m = pattern.search(text)
            if not m:
                continue
            # Tomcat generic "HTTP Status 500" is common — require Tomcat cue
            if detector_id == "fw_tomcat":
                if not re.search(r"Tomcat|type Status report|Apache Tomcat", text, re.I):
                    continue
            seen_fw.add(framework)
            conf = confidence
            matches.append(
                build_raw_error_match(
                    detector_id=detector_id,
                    family=DETECTOR_FAMILY_FRAMEWORK,
                    text=text,
                    match_start=m.start(),
                    match_end=m.end(),
                    exception_type=exc,
                    confidence=conf,
                    category_hint=CATEGORY_FRAMEWORK,
                    language=language or LANG_UNKNOWN,
                    metadata={
                        "framework": framework,
                        "technologies": [framework],
                        "server": framework if framework in ("tomcat", "jetty") else None,
                    },
                )
            )
            if len(matches) >= self._max:
                break
        return matches
