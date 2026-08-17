from __future__ import annotations

import json
import mimetypes
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from ctf_harness.operational.models import CredentialRef

from .credentials import CredentialResolver
from .models import CompetitionChallengeSnapshot, DownloadedArtifact


class CTFdAuthMode(str, Enum):
    TOKEN = "token"
    COOKIE = "cookie"


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    def request(self, *, method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> HttpResponse: ...


class UrllibTransport:
    def request(self, *, method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> HttpResponse:
        request = Request(url=url, method=method, headers=dict(headers), data=body)
        try:
            with urlopen(request, timeout=20.0) as response:  # nosec - URL scope is enforced by CTFdAdapter
                return HttpResponse(int(response.status), dict(response.headers.items()), response.read())
        except HTTPError as exc:
            return HttpResponse(int(exc.code), dict(exc.headers.items()), exc.read())
        except URLError as exc:
            raise RuntimeError(f"CTFd transport failed: {exc}") from exc


class CTFdAdapter:
    """Native CTFd platform adapter.

    Platform responses remain normalized snapshots. Challenge identity becomes
    authoritative only after a ChallengeManifest is built and artifacts are
    admitted by the existing harness path.
    """

    def __init__(
        self,
        base_url: str,
        *,
        credential_ref: CredentialRef,
        credential_resolver: CredentialResolver,
        auth_mode: CTFdAuthMode = CTFdAuthMode.TOKEN,
        cookie_name: str = "session",
        transport: HttpTransport | None = None,
    ):
        parsed = urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("CTFd base_url must be an absolute http(s) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("CTFd base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("CTFd base_url must not contain query/fragment")
        if not isinstance(credential_ref, CredentialRef):
            raise ValueError("credential_ref must be CredentialRef")
        if not isinstance(credential_resolver, CredentialResolver):
            raise ValueError("credential_resolver must be CredentialResolver")
        if not isinstance(auth_mode, CTFdAuthMode):
            raise ValueError("auth_mode must be CTFdAuthMode")
        if not isinstance(cookie_name, str) or not cookie_name.strip():
            raise ValueError("cookie_name must be non-empty")
        self.base_url = base_url.rstrip("/")
        self._origin = (parsed.scheme, parsed.hostname, parsed.port)
        self.credential_ref = credential_ref
        self.credential_resolver = credential_resolver
        self.auth_mode = auth_mode
        self.cookie_name = cookie_name
        self.transport = transport or UrllibTransport()

    def _scoped_url(self, path_or_url: str) -> str:
        url = urljoin(self.base_url + "/", path_or_url)
        parsed = urlsplit(url)
        origin = (parsed.scheme, parsed.hostname, parsed.port)
        if origin != self._origin:
            raise ValueError("CTFd adapter refused cross-origin URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("CTFd adapter refused URL credentials")
        return url

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        with self.credential_resolver.resolve(self.credential_ref) as secret:
            value = secret.reveal_text()
            if self.auth_mode is CTFdAuthMode.TOKEN:
                headers = {"Authorization": f"Token {value}"}
            else:
                headers = {"Cookie": f"{self.cookie_name}={value}"}
        headers["Accept"] = "application/json"
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def _request(self, method: str, path_or_url: str, *, payload: dict | None = None) -> HttpResponse:
        body = None if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        response = self.transport.request(
            method=method,
            url=self._scoped_url(path_or_url),
            headers=self._headers(json_body=payload is not None),
            body=body,
        )
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"CTFd HTTP status {response.status}")
        return response

    def _json(self, method: str, path_or_url: str, *, payload: dict | None = None):
        response = self._request(method, path_or_url, payload=payload)
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("CTFd response is not valid JSON") from exc
        if not isinstance(parsed, dict) or parsed.get("success") is not True:
            raise RuntimeError("CTFd API response did not report success")
        return parsed.get("data")

    @staticmethod
    def _snapshot(raw: dict) -> CompetitionChallengeSnapshot:
        if not isinstance(raw, dict):
            raise RuntimeError("CTFd challenge payload must be an object")
        files = raw.get("files") or ()
        if not isinstance(files, (list, tuple)):
            files = ()
        return CompetitionChallengeSnapshot(
            platform="ctfd",
            challenge_id=str(raw.get("id", "")),
            name=str(raw.get("name", "")),
            description=str(raw.get("description", "")),
            category=(str(raw["category"]) if raw.get("category") is not None else None),
            file_urls=tuple(str(item) for item in files if isinstance(item, str) and item),
            connection_info=(str(raw["connection_info"]) if raw.get("connection_info") else None),
        )

    def validate_session(self) -> bool:
        data = self._json("GET", "/api/v1/challenges")
        return isinstance(data, list)

    def list_challenges(self):
        data = self._json("GET", "/api/v1/challenges")
        if not isinstance(data, list):
            raise RuntimeError("CTFd challenge list payload must be a list")
        return tuple(self._snapshot(item) for item in data)

    def get_challenge(self, challenge_id: str) -> CompetitionChallengeSnapshot:
        if not isinstance(challenge_id, str) or not challenge_id.strip() or "/" in challenge_id:
            raise ValueError("challenge_id must be a simple non-empty string")
        raw = self._json("GET", f"/api/v1/challenges/{challenge_id}")
        snapshot = self._snapshot(raw)
        if not snapshot.file_urls:
            try:
                files = self._json("GET", f"/api/v1/challenges/{challenge_id}/files")
            except RuntimeError:
                files = None
            if isinstance(files, list):
                snapshot = CompetitionChallengeSnapshot(
                    platform=snapshot.platform,
                    challenge_id=snapshot.challenge_id,
                    name=snapshot.name,
                    description=snapshot.description,
                    category=snapshot.category,
                    file_urls=tuple(str(item) for item in files if isinstance(item, str) and item),
                    connection_info=snapshot.connection_info,
                )
        return snapshot

    def download(self, file_url: str) -> DownloadedArtifact:
        response = self._request("GET", file_url)
        path = PurePosixPath(urlsplit(self._scoped_url(file_url)).path)
        name = path.name or "download.bin"
        if name in {".", ".."} or "/" in name or "\\" in name:
            raise ValueError("unsafe CTFd download filename")
        return DownloadedArtifact(name, response.body, self._scoped_url(file_url))

    def submit_flag(self, challenge_id: str, candidate: str) -> bool:
        if not isinstance(candidate, str) or not candidate:
            raise ValueError("flag candidate must be non-empty")
        cid: int | str = int(challenge_id) if str(challenge_id).isdigit() else challenge_id
        data = self._json(
            "POST",
            "/api/v1/challenges/attempt",
            payload={"challenge_id": cid, "submission": candidate},
        )
        if not isinstance(data, dict):
            return False
        status = str(data.get("status", "")).lower()
        return status in {"correct", "already_solved", "already solved"}
