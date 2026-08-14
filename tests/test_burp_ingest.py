"""Localhost ingest: Talos offers a trace instead of stamping X-Talos-*."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from talos.burp.ingest import offer_trace, reset_ingest_state
from talos.burp.trace import BurpTrace, ENGINE_UNAUTH, GROUP_ENDPOINTS


def test_offer_trace_posts_flat_json(monkeypatch, tmp_path) -> None:
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b'{"ok":true,"service":"talos-burp"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            received.append(payload)
            self.send_response(204)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        monkeypatch.setattr("talos.burp.ingest.Path.home", lambda: tmp_path)
        (tmp_path / ".talos").mkdir()
        (tmp_path / ".talos" / "burp-ingest.port").write_text(
            str(port), encoding="utf-8"
        )
        reset_ingest_state()
        trace = BurpTrace(
            engine=ENGINE_UNAUTH,
            group=GROUP_ENDPOINTS,
            endpoint_label="DELETE /api/Feedbacks/1",
            host="myapp.local:3000",
            endpoint_id="ep-1",
            extras={"technique": "baseline", "variant": "x_forwarded_for_localhost"},
            project_id="juice",
            project_name="Juice Shop",
            record_id="rec-42",
        )
        assert offer_trace(
            trace,
            method="DELETE",
            host="myapp.local:3000",
            path="/api/Feedbacks/1",
        )
        assert received[0]["engine"] == "unauth"
        assert received[0]["endpoint"] == "DELETE /api/Feedbacks/1"
        assert received[0]["method"] == "DELETE"
        assert received[0]["path"] == "/api/Feedbacks/1"
        assert received[0]["variant"] == "x_forwarded_for_localhost"
        assert received[0]["project_id"] == "juice"
        assert received[0]["project_name"] == "Juice Shop"
        assert received[0]["record_id"] == "rec-42"
    finally:
        server.shutdown()
        reset_ingest_state()
