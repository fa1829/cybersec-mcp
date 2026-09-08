"""Outbound HTTP with the guard rails switched on.

Every request made by this server goes through ``fetch``. That gives one place
to enforce: SSRF policy, redirect re-validation, per-host rate limiting,
response size caps, and result caching.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict, deque
from urllib.parse import urljoin, urlsplit

import httpx

from . import config
from .safety import BlockedTarget, Target, redact, validate_target


class RateLimited(RuntimeError):
    """Upstream asked us to slow down, or our own limiter did."""


# ── per-host token bucket ────────────────────────────────────────────────
_windows: dict[str, deque[float]] = {}
_lock = asyncio.Lock()


async def _throttle(host: str) -> None:
    limit = config.RATE_LIMITS.get(host, config.RATE_LIMITS["*"])
    async with _lock:
        now = time.monotonic()
        window = _windows.setdefault(host, deque())
        while window and now - window[0] > 60.0:
            window.popleft()
        if len(window) >= limit:
            wait = 60.0 - (now - window[0])
            raise RateLimited(
                f"local rate limit for {host} reached ({limit}/min). "
                f"Retry in {wait:.0f}s — this protects the free-tier API quota."
            )
        window.append(now)


# ── tiny TTL cache ───────────────────────────────────────────────────────
_cache: OrderedDict[str, tuple[float, str]] = OrderedDict()


def cache_get(key: str) -> str | None:
    hit = _cache.get(key)
    if hit is None:
        return None
    expires, value = hit
    if expires < time.time():
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return value


def cache_put(key: str, value: str) -> None:
    _cache[key] = (time.time() + config.CACHE_TTL_S, value)
    _cache.move_to_end(key)
    while len(_cache) > config.CACHE_MAX_ENTRIES:
        _cache.popitem(last=False)


def cache_clear() -> None:
    _cache.clear()


# ── the one outbound path ────────────────────────────────────────────────
async def fetch(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    validate: bool = True,
    allow_private: bool | None = None,
) -> tuple[httpx.Response, list[Target]]:
    """GET a URL under policy. Returns the final response and the hop chain.

    Redirects are followed manually so that *every* hop is re-validated.
    Following redirects automatically is the standard way an SSRF filter gets
    bypassed: the first URL passes, then the server 302s you to 169.254.169.254.
    """
    hops: list[Target] = []
    current = url
    request_headers = {"User-Agent": config.USER_AGENT, **(headers or {})}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.HTTP_TIMEOUT_S),
        follow_redirects=False,
    ) as client:
        for hop in range(config.MAX_REDIRECTS + 1):
            if validate:
                target = validate_target(current, allow_private=allow_private)
            else:
                parts = urlsplit(current)
                target = Target(
                    url=current,
                    scheme=parts.scheme,
                    host=parts.hostname or "",
                    port=parts.port or (443 if parts.scheme == "https" else 80),
                    addresses=(),
                )
            hops.append(target)

            await _throttle(target.host)
            response = await client.get(current, headers=request_headers)

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    return response, hops
                if hop == config.MAX_REDIRECTS:
                    raise BlockedTarget(
                        f"redirect limit ({config.MAX_REDIRECTS}) exceeded starting from {url}."
                    )
                current = urljoin(current, location)
                continue

            if len(response.content) > config.MAX_RESPONSE_BYTES:
                raise RateLimited(
                    f"response from {target.host} exceeded "
                    f"{config.MAX_RESPONSE_BYTES:,} bytes and was discarded."
                )
            return response, hops

    raise BlockedTarget("redirect loop")  # pragma: no cover — loop always returns


def describe_error(exc: Exception) -> str:
    """Turn an exception into a short, secret-free, model-safe line."""
    if isinstance(exc, BlockedTarget):
        return f"🚫 Blocked by network policy: {exc}"
    if isinstance(exc, RateLimited):
        return f"⏳ {exc}"
    if isinstance(exc, httpx.TimeoutException):
        return f"⏱️ Upstream request timed out after {config.HTTP_TIMEOUT_S:.0f}s."
    if isinstance(exc, httpx.HTTPError):
        return redact(f"🌐 HTTP error: {type(exc).__name__}: {exc}")
    return redact(f"⚠️ {type(exc).__name__}: {exc}")


def redirect_note(hops: list[Target]) -> str:
    """Report the redirect chain — a finding in its own right."""
    if len(hops) <= 1:
        return ""
    chain = " → ".join(f"{h.scheme}://{h.host}:{h.port}" for h in hops)
    return f"\n> ↪️ Followed {len(hops) - 1} redirect(s), each re-validated: {chain}\n"
