from __future__ import annotations

import json
import math
import time
from collections.abc import Callable
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_VERSION = "2026-03-10"
READ_ATTEMPTS = 4
RATE_LIMIT_FALLBACK_SECONDS = 60


class AmbiguousRequestError(RuntimeError):
    """Raised when a mutating request may have reached GitHub."""


class GitHubTransport:
    def __init__(
        self,
        token: str,
        *,
        opener: Callable[..., Any] = urlopen,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise ValueError("GitHub token must not be empty")
        self._token = token
        self._opener = opener
        self._sleep = sleep
        self._now = now
        self._api_url = api_url.rstrip("/")

    def get_json(self, path: str) -> object:
        request = self._request(path)
        for request_number in range(READ_ATTEMPTS):
            try:
                with self._opener(request, timeout=30) as response:
                    if response.status != 200:
                        raise RuntimeError(
                            f"GitHub read request returned HTTP {response.status}"
                        )
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as error:
                delay = self._http_retry_delay(error, request_number)
                if delay is not None and request_number < READ_ATTEMPTS - 1:
                    self._sleep(delay)
                    continue
                raise RuntimeError(
                    f"GitHub read request returned HTTP {error.code}"
                ) from error
            except URLError as error:
                if request_number < READ_ATTEMPTS - 1:
                    self._sleep(2**request_number)
                    continue
                raise RuntimeError(
                    "GitHub read request failed after four attempts"
                ) from error
        raise AssertionError("unreachable")

    def post_mutation(self, path: str) -> None:
        request = self._request(path, method="POST", data=b"{}")
        try:
            with self._opener(request, timeout=30) as response:
                if response.status != 201:
                    raise RuntimeError(
                        f"GitHub mutation request returned HTTP {response.status}"
                    )
        except HTTPError as error:
            if error.code in {409, 422}:
                raise AmbiguousRequestError(
                    f"GitHub mutation request returned HTTP {error.code}"
                ) from error
            raise RuntimeError(
                f"GitHub mutation request returned HTTP {error.code}"
            ) from error
        except URLError as error:
            raise AmbiguousRequestError(
                "GitHub mutation request ended without a definitive response"
            ) from error

    def _request(
        self, path: str, *, method: str = "GET", data: bytes | None = None
    ) -> Request:
        return Request(
            f"{self._api_url}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "saltyorg/github-actions",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )

    def _http_retry_delay(
        self, error: HTTPError, request_number: int
    ) -> float | None:
        retry_after = _retry_after_seconds(error, self._now())
        if 500 <= error.code < 600:
            return retry_after if retry_after is not None else 2**request_number
        if not _is_rate_limit_error(error):
            return None
        if retry_after is not None:
            return retry_after
        reset_delay = _rate_limit_reset_seconds(error, self._now())
        return reset_delay if reset_delay is not None else RATE_LIMIT_FALLBACK_SECONDS


def _retry_after_seconds(error: HTTPError, now: float) -> float | None:
    value = error.headers.get("Retry-After") if error.headers else None
    if not value:
        return None
    try:
        seconds = int(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        return max(0, math.ceil(retry_at.timestamp() - now))
    return seconds if seconds >= 0 else None


def _rate_limit_reset_seconds(error: HTTPError, now: float) -> float | None:
    value = error.headers.get("X-RateLimit-Reset") if error.headers else None
    if not value:
        return None
    try:
        reset_at = int(value)
    except ValueError:
        return None
    return max(0, math.ceil(reset_at - now))


def _is_rate_limit_error(error: HTTPError) -> bool:
    if error.code == 429:
        return True
    if error.code != 403:
        return False
    if error.headers:
        if error.headers.get("Retry-After"):
            return True
        if error.headers.get("X-RateLimit-Remaining") == "0":
            return True
    try:
        payload = json.loads(error.read().decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    message = payload.get("message") if isinstance(payload, dict) else None
    return isinstance(message, str) and "rate limit" in message.casefold()
