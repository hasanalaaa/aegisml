"""Small, dependency-free guards for untrusted scan inputs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Mapping
from urllib.parse import urljoin, urlparse


class InputSecurityError(ValueError):
    """Raised when an upload or remote download fails a security invariant."""


_HUB_HOSTS = frozenset({"huggingface.co", "www.huggingface.co"})
_DOWNLOAD_SUFFIXES = ("huggingface.co", "hf.co")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def sanitize_filename(name: str) -> str:
    """Return a display-only basename for POSIX and Windows-style inputs."""
    basename = (name or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    basename = "".join(char for char in basename if char.isprintable() and char != "\x00")
    if basename in {"", ".", ".."}:
        return "unknown"
    return basename[:500]


def _normalized_hostname(raw_hostname: str | None) -> str:
    if not raw_hostname:
        raise InputSecurityError("Download URL must include a hostname")
    try:
        return raw_hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InputSecurityError("Download URL contains an invalid hostname") from exc


def _is_download_host(hostname: str) -> bool:
    return any(
        hostname == suffix or hostname.endswith(f".{suffix}")
        for suffix in _DOWNLOAD_SUFFIXES
    )


def validate_hf_download_url(url: str, *, initial: bool) -> str:
    """Validate an initial Hub URL or a trusted Hub/CDN redirect target."""
    cleaned = (url or "").strip()
    if not cleaned or len(cleaned) > 4096:
        raise InputSecurityError("Invalid download URL")
    if any(ord(char) < 32 or ord(char) == 127 for char in cleaned):
        raise InputSecurityError("Download URL contains control characters")

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https":
        raise InputSecurityError("Only HTTPS Hugging Face downloads are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise InputSecurityError("Credentials are not allowed inside download URLs")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputSecurityError("Download URL contains an invalid port") from exc
    if port not in (None, 443):
        raise InputSecurityError("Only HTTPS port 443 is allowed")

    hostname = _normalized_hostname(parsed.hostname)
    allowed = hostname in _HUB_HOSTS if initial else _is_download_host(hostname)
    if not allowed:
        raise InputSecurityError("Download host is not a trusted Hugging Face endpoint")
    return cleaned


async def _assert_public_resolution(url: str) -> None:
    """Reject loopback, private, link-local, and otherwise non-global DNS."""
    parsed = urlparse(url)
    hostname = _normalized_hostname(parsed.hostname)
    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo,
            hostname,
            443,
            0,
            socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise InputSecurityError("Download hostname could not be resolved") from exc

    resolved = set()
    for family, _, _, _, sockaddr in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = str(sockaddr[0]).split("%", 1)[0]
        try:
            candidate = ipaddress.ip_address(address)
        except ValueError as exc:
            raise InputSecurityError("Download hostname resolved unexpectedly") from exc
        mapped = getattr(candidate, "ipv4_mapped", None)
        if not candidate.is_global or (mapped is not None and not mapped.is_global):
            raise InputSecurityError("Download hostname resolved to a non-public address")
        resolved.add(candidate)

    if not resolved:
        raise InputSecurityError("Download hostname did not resolve to a public address")


def _hostname(url: str) -> str:
    return _normalized_hostname(urlparse(url).hostname)


@asynccontextmanager
async def secure_hf_stream(
    client: Any,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    max_redirects: int = 5,
) -> AsyncIterator[Any]:
    """Open a bounded, manually validated Hugging Face download stream.

    Redirects are restricted to Hugging Face's documented ``hf.co`` and
    ``huggingface.co`` CDN suffixes. DNS is checked at every hop, and secrets
    are sent only to the two Hub API hosts, never to storage/CDN hosts.
    """
    current = validate_hf_download_url(url, initial=True)
    request_headers = dict(headers or {})

    for redirect_count in range(max_redirects + 1):
        current = validate_hf_download_url(current, initial=redirect_count == 0)
        await _assert_public_resolution(current)
        hop_headers = request_headers if _hostname(current) in _HUB_HOSTS else {}

        async with client.stream("GET", current, headers=hop_headers) as response:
            if response.status_code in _REDIRECT_STATUSES:
                if redirect_count >= max_redirects:
                    raise InputSecurityError("Download exceeded the redirect limit")
                location = response.headers.get("location")
                if not location:
                    raise InputSecurityError("Download redirect omitted its destination")
                current = validate_hf_download_url(
                    urljoin(current, location),
                    initial=False,
                )
                continue

            yield response
            return

    raise InputSecurityError("Download exceeded the redirect limit")


def validate_model_header(extension: str, size: int, head: bytes) -> None:
    """Fail closed for formats with stable, mandatory container headers."""
    if size <= 0:
        raise InputSecurityError("Downloaded model is empty")
    if extension == ".gguf" and (size < 4 or head[:4] != b"GGUF"):
        raise InputSecurityError("Magic bytes mismatch for GGUF")
    if extension == ".safetensors" and (size <= 8 or head[8:9] != b"{"):
        raise InputSecurityError("Magic bytes mismatch for safetensors")
