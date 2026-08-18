"""SQLi detector: new DBMS errors vs baseline, UNION, time delay."""

from talos.sqli.detect import analyze_sqli_response, collect_signatures
from talos.sqli.models import VERDICT_SECURE, VERDICT_SQLI


ISSUE7_BODY = (
    b'{"error":"(\'22007\', \'[22007] [Microsoft][ODBC Driver 17 for SQL Server]'
    b"[SQL Server]Conversion failed when converting date and/or time from "
    b"character string. (241) (SQLExecDirectW)')\",\"ok\":false}"
)


def test_collects_sql_server_odbc_signatures() -> None:
    hits = collect_signatures(ISSUE7_BODY.decode())
    kinds = {h[1] for h in hits}
    assert "sqlserver" in kinds
    patterns = {h[0] for h in hits}
    assert any("Conversion failed" in p for p in patterns)
    assert any("SQLExecDirectW" in p for p in patterns)


def test_same_baseline_error_is_not_sqli() -> None:
    verdict, hint, dbms, _ = analyze_sqli_response(
        baseline_body=ISSUE7_BODY,
        probe_body=ISSUE7_BODY,
        family="error",
        delay_s=0,
        elapsed_s=0.1,
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""
    assert dbms == "sqlserver"


def test_new_syntax_error_vs_conversion_baseline_is_sqli() -> None:
    probe = (
        b'{"error":"[Microsoft][ODBC Driver 17 for SQL Server][SQL Server]'
        b"Unclosed quotation mark after the character string.\"}"
    )
    verdict, hint, dbms, evidence = analyze_sqli_response(
        baseline_body=ISSUE7_BODY,
        probe_body=probe,
        family="error",
        delay_s=0,
        elapsed_s=0.1,
    )
    assert verdict == VERDICT_SQLI
    assert hint == "error_based"
    assert dbms == "sqlserver"
    assert "Unclosed quotation" in evidence


def test_clean_baseline_plus_sql_error_is_sqli() -> None:
    verdict, hint, dbms, _ = analyze_sqli_response(
        baseline_body=b'{"ok":true}',
        probe_body=ISSUE7_BODY,
        family="error",
        delay_s=0,
        elapsed_s=0.05,
    )
    assert verdict == VERDICT_SQLI
    assert hint == "error_based"
    assert dbms == "sqlserver"


def test_union_column_count_is_sqli() -> None:
    probe = (
        b"All queries combined using a UNION operator must have an equal "
        b"number of expressions"
    )
    verdict, hint, _, _ = analyze_sqli_response(
        baseline_body=b"ok",
        probe_body=probe,
        family="union",
        delay_s=0,
        elapsed_s=0.05,
    )
    assert verdict == VERDICT_SQLI
    assert hint == "union"


def test_time_delay_is_sqli() -> None:
    verdict, hint, _, evidence = analyze_sqli_response(
        baseline_body=b"ok",
        probe_body=b"ok",
        family="time",
        delay_s=5.0,
        elapsed_s=4.2,
    )
    assert verdict == VERDICT_SQLI
    assert hint == "time_delay"
    assert "elapsed=" in evidence


def test_fast_time_payload_is_secure() -> None:
    verdict, hint, _, _ = analyze_sqli_response(
        baseline_body=b"ok",
        probe_body=b"ok",
        family="time",
        delay_s=5.0,
        elapsed_s=0.2,
    )
    assert verdict == VERDICT_SECURE
    assert hint == ""
