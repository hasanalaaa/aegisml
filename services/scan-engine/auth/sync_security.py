"""Fail-closed validation for the server-to-server auth sync secret."""

from __future__ import annotations

import hmac


class SyncSecretUnavailable(RuntimeError):
    """The service has no configured sync secret."""


class InvalidSyncSecret(ValueError):
    """The caller did not provide the configured sync secret."""


def verify_sync_secret(configured: str, provided: str | None) -> None:
    if not configured:
        raise SyncSecretUnavailable
    if not provided or not hmac.compare_digest(provided, configured):
        raise InvalidSyncSecret
