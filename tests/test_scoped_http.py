from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ctf_harness.tools.scoped_http import ChallengeHttpClient


class GoodHandler(BaseHTTPRequestHandler):
    redirect_target = None

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.redirect_target)
            self.end_headers()
            return
        body = b"flag{scoped_http_fixture}"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class OtherHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"other-origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_scoped_http_allows_only_admitted_origin_and_returns_observation() -> None:
    server, thread = _serve(GoodHandler)
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        client = ChallengeHttpClient((origin,), timeout_seconds=2.0)
        result = client.request(origin + "/")
        assert result["response"]["status"] == 200
        assert base64.b64decode(result["response"]["body_b64"]) == b"flag{scoped_http_fixture}"
        assert result["truth_authority"] == "observation_only"
        tool = client.make_tool()
        assert tool.name == "scoped_http"
        assert tool.provenance["credential_boundary"] == "platform_credentials_not_accepted"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_scoped_http_rejects_sensitive_headers_and_non_admitted_origin() -> None:
    server, thread = _serve(GoodHandler)
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        client = ChallengeHttpClient((origin,))
        with pytest.raises(ValueError, match="credential headers"):
            client.request(origin + "/", headers={"Authorization": "Bearer secret"})
        with pytest.raises(ValueError, match="credential headers"):
            client.request(origin + "/", headers={"Cookie": "session=secret"})
        with pytest.raises(ValueError, match="non-admitted origin"):
            client.request("http://127.0.0.1:1/")
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_scoped_http_rejects_cross_origin_redirect() -> None:
    allowed, allowed_thread = _serve(GoodHandler)
    other, other_thread = _serve(OtherHandler)
    try:
        allowed_origin = f"http://127.0.0.1:{allowed.server_port}"
        other_origin = f"http://127.0.0.1:{other.server_port}"
        GoodHandler.redirect_target = other_origin + "/landing"
        client = ChallengeHttpClient((allowed_origin,), timeout_seconds=2.0)
        with pytest.raises(ValueError, match="non-admitted origin"):
            client.request(allowed_origin + "/redirect")
    finally:
        allowed.shutdown()
        other.shutdown()
        allowed_thread.join(timeout=2)
        other_thread.join(timeout=2)
