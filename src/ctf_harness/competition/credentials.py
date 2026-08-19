from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ctf_harness.operational.models import CredentialKind, CredentialRef


class SecretHandle:
    """Transient mutable secret container with redacted representation."""

    def __init__(self, value: str):
        if not isinstance(value, str) or not value:
            raise ValueError("secret value must be non-empty")
        self._value = bytearray(value.encode("utf-8"))
        self._closed = False

    def reveal_text(self) -> str:
        if self._closed:
            raise RuntimeError("secret handle is closed")
        return bytes(self._value).decode("utf-8")

    def close(self) -> None:
        if not self._closed:
            for index in range(len(self._value)):
                self._value[index] = 0
            self._closed = True

    def __enter__(self) -> "SecretHandle":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return "SecretHandle(<redacted>)"


class CredentialResolver:
    """Resolve CredentialRef just-in-time; raw values are never descriptors/state."""

    def __init__(
        self,
        *,
        keyring_getter: Callable[[str], str | None] | None = None,
        session_getter: Callable[[str], str | None] | None = None,
        environ: Mapping[str, str] | None = None,
    ):
        self.keyring_getter = keyring_getter
        self.session_getter = session_getter
        self.environ = os.environ if environ is None else environ

    def resolve(self, ref: CredentialRef) -> SecretHandle:
        if not isinstance(ref, CredentialRef):
            raise ValueError("credential reference must be CredentialRef")
        if ref.kind is CredentialKind.ENV:
            value = self.environ.get(ref.locator)
        elif ref.kind is CredentialKind.KEYRING:
            value = None if self.keyring_getter is None else self.keyring_getter(ref.locator)
        elif ref.kind is CredentialKind.SESSION:
            value = None if self.session_getter is None else self.session_getter(ref.locator)
        else:
            value = None
        if not value:
            raise RuntimeError(f"credential reference cannot be resolved: {ref.kind.value}:{ref.locator}")
        return SecretHandle(value)


@dataclass(frozen=True)
class SecretRedactor:
    """Defense-in-depth log redaction; not a substitute for credential isolation."""

    secrets: tuple[str, ...] = ()

    _HEADER_RE = re.compile(r"(?im)^(authorization|cookie)\s*:\s*.*$")
    _SENSITIVE_QUERY = {"token", "api_key", "apikey", "key", "session", "auth", "authorization"}

    def redact_text(self, text: str) -> str:
        rendered = str(text)
        for secret in sorted((s for s in self.secrets if s), key=len, reverse=True):
            rendered = rendered.replace(secret, "<redacted>")
        return self._HEADER_RE.sub(lambda m: f"{m.group(1)}: <redacted>", rendered)

    def sanitize_url(self, url: str) -> str:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        query = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            query.append((key, "<redacted>" if key.lower() in self._SENSITIVE_QUERY else self.redact_text(value)))
        return urlunsplit((parsed.scheme, host, parsed.path, urlencode(query), parsed.fragment))
