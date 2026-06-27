"""
AegisML Cache Module — Redis-backed caching with graceful fallback

Every function is safe to call even when Redis is unavailable:
  - get_cache  → returns None
  - set_cache  → returns False
  - delete_cache → returns False
  - delete_pattern → returns 0
  - invalidate_scan → no-op

TTL defaults (seconds):
  stats   = 60
  threats = 300
  scans   = 30
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("aegisml.cache")

# TTL constants (seconds)
TTL_STATS: int = 60
TTL_THREATS: int = 300
TTL_SCAN: int = 30
TTL_DEFAULT: int = 300

# Cache key prefixes
PREFIX_STATS: str = "aegisml:stats"
PREFIX_THREATS: str = "aegisml:threats"
PREFIX_SCAN: str = "aegisml:scan:"


def _get_redis():
    """Import redis_client lazily to avoid circular imports."""
    from database import redis_client

    return redis_client


async def get_cache(key: str) -> Optional[Any]:
    """Retrieve a cached value by key.  Returns None on miss or error."""
    client = _get_redis()
    if client is None:
        return None
    try:
        raw: Optional[str] = await client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.debug("Cache deserialize error for key=%s: %s", key, exc)
        # Corrupted entry — silently delete it
        try:
            await client.delete(key)
        except Exception:
            pass
        return None
    except Exception as exc:
        logger.warning("Cache GET error for key=%s: %s", key, exc)
        return None


async def set_cache(key: str, value: Any, ttl: int = TTL_DEFAULT) -> bool:
    """Store a value with TTL.  Returns True on success."""
    client = _get_redis()
    if client is None:
        return False
    try:
        serialised = json.dumps(value, default=str, ensure_ascii=False)
        await client.setex(key, ttl, serialised)
        return True
    except (TypeError, ValueError) as exc:
        logger.warning("Cache serialization error for key=%s: %s", key, exc)
        return False
    except Exception as exc:
        logger.warning("Cache SET error for key=%s: %s", key, exc)
        return False


async def delete_cache(key: str) -> bool:
    """Delete a single cached key.  Returns True on success."""
    client = _get_redis()
    if client is None:
        return False
    try:
        await client.delete(key)
        return True
    except Exception as exc:
        logger.warning("Cache DELETE error for key=%s: %s", key, exc)
        return False


async def delete_pattern(pattern: str) -> int:
    """Delete all keys matching a glob pattern.  Returns count deleted."""
    client = _get_redis()
    if client is None:
        return 0
    deleted = 0
    try:
        cursor: int = 0
        while True:
            cursor, keys = await client.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                await client.delete(*keys)
                deleted += len(keys)
            if cursor == 0:
                break
    except Exception as exc:
        logger.warning("Cache pattern-delete error for pattern=%s: %s", pattern, exc)
    return deleted


async def invalidate_scan(scan_id: str) -> None:
    """Remove a specific scan from cache and bust the stats cache."""
    await delete_cache(f"{PREFIX_SCAN}{scan_id}")
    await delete_cache(PREFIX_STATS)


# ── Convenience wrappers for common cache operations ─────────────────


async def get_cached_stats() -> Optional[dict]:
    """Get cached /stats response."""
    return await get_cache(PREFIX_STATS)


async def set_cached_stats(data: dict) -> bool:
    """Cache /stats response for 60 s."""
    return await set_cache(PREFIX_STATS, data, TTL_STATS)


async def get_cached_threats() -> Optional[dict]:
    """Get cached /threats/patterns response."""
    return await get_cache(PREFIX_THREATS)


async def set_cached_threats(data: dict) -> bool:
    """Cache /threats/patterns response for 300 s."""
    return await set_cache(PREFIX_THREATS, data, TTL_THREATS)


async def get_cached_scan(scan_id: str) -> Optional[dict]:
    """Get a cached individual scan result."""
    return await get_cache(f"{PREFIX_SCAN}{scan_id}")


async def set_cached_scan(scan_id: str, data: dict) -> bool:
    """Cache an individual scan result for 30 s."""
    return await set_cache(f"{PREFIX_SCAN}{scan_id}", data, TTL_SCAN)
