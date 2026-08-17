from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from harness.core.tools import SideEffect, ToolSpec


_SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization"}


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("challenge HTTP URL must be absolute http(s)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("challenge HTTP URL must not contain credentials")
    return parsed.scheme, parsed.hostname.lower(), parsed.port


def _canonical_origin(url: str) -> str:
    scheme, host, port = _origin(url)
    default = 80 if scheme == "http" else 443
    host_for_authority = f"[{host}]" if ":" in host else host
    authority = host_for_authority if port in {None, default} else f"{host_for_authority}:{port}"
    return f"{scheme}://{authority}"


class _ScopedRedirect(HTTPRedirectHandler):
    def __init__(self, client: "ChallengeHttpClient"):
        super().__init__()
        self.client = client

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.client.require_allowed(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class ChallengeHttpClient:
    allowed_origins: tuple[str, ...]
    timeout_seconds: float = 15.0
    max_response_bytes: int = 2 * 1024 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_origins, tuple) or not self.allowed_origins:
            raise ValueError("challenge HTTP client requires at least one allowed origin")
        normalized = tuple(_canonical_origin(item) for item in self.allowed_origins)
        if len(set(normalized)) != len(normalized):
            raise ValueError("challenge HTTP allowed origins must be unique")
        object.__setattr__(self, "allowed_origins", normalized)
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0:
            raise ValueError("HTTP timeout must be positive")
        if not isinstance(self.max_response_bytes, int) or isinstance(self.max_response_bytes, bool) or self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")

    def require_allowed(self, url: str) -> str:
        if _canonical_origin(url) not in self.allowed_origins:
            raise ValueError("challenge HTTP request refused non-admitted origin")
        parsed = urlsplit(url)
        if parsed.fragment:
            parsed = parsed._replace(fragment="")
        return urlunsplit(parsed)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body_b64: str | None = None,
    ) -> dict:
        target = self.require_allowed(url)
        method = str(method).upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError("unsupported challenge HTTP method")
        clean_headers: dict[str, str] = {}
        for key, value in dict(headers or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("HTTP headers must map strings to strings")
            if key.lower() in _SENSITIVE_HEADERS:
                raise ValueError("challenge HTTP tool does not accept platform/sensitive credential headers")
            if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                raise ValueError("HTTP header contains newline")
            clean_headers[key] = value
        body = None
        if body_b64 is not None:
            if not isinstance(body_b64, str):
                raise ValueError("body_b64 must be a string")
            try:
                body = base64.b64decode(body_b64, validate=True)
            except Exception as exc:
                raise ValueError("body_b64 is not valid base64") from exc
        opener = build_opener(_ScopedRedirect(self))
        request = Request(target, method=method, headers=clean_headers, data=body)
        try:
            with opener.open(request, timeout=float(self.timeout_seconds)) as response:
                data = response.read(self.max_response_bytes + 1)
                status = int(response.status)
                final_url = self.require_allowed(response.geturl())
                response_headers = dict(response.headers.items())
        except HTTPError as exc:
            data = exc.read(self.max_response_bytes + 1)
            status = int(exc.code)
            final_url = self.require_allowed(exc.geturl())
            response_headers = dict(exc.headers.items())
        except URLError as exc:
            raise RuntimeError(f"challenge HTTP transport failed: {exc}") from exc
        if len(data) > self.max_response_bytes:
            raise RuntimeError("challenge HTTP response exceeds configured byte limit")
        return {
            "schema_version": "ctf-scoped-http-observation-v1",
            "request": {
                "method": method,
                "url": target,
                "credential_headers_allowed": False,
            },
            "response": {
                "status": status,
                "final_url": final_url,
                "content_type": response_headers.get("Content-Type"),
                "body_b64": base64.b64encode(data).decode("ascii"),
                "bytes": len(data),
            },
            "scope": {"allowed_origins": list(self.allowed_origins)},
            "truth_authority": "observation_only",
        }

    def make_tool(self) -> ToolSpec:
        return ToolSpec(
            name="scoped_http",
            description=(
                "Issue a bounded HTTP request only to an admitted challenge origin. "
                "Cross-origin redirects and Authorization/Cookie headers are rejected."
            ),
            handler=lambda url, method="GET", headers=None, body_b64=None: self.request(
                url, method=method, headers=headers, body_b64=body_b64
            ),
            side_effect=SideEffect.EXTERNAL,
            idempotent=False,
            permission="auto",
            failure_modes=["origin_not_admitted", "cross_origin_redirect", "network_error", "response_too_large"],
            provenance={
                "kind": "ctf_scoped_http",
                "schema": "ctf-scoped-http-observation-v1",
                "credential_boundary": "platform_credentials_not_accepted",
                "truth_authority": "none",
            },
        )
