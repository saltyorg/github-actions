from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_VERSION = "2026-03-10"
TRANSIENT_STATUS = {429, *range(500, 600)}


class AmbiguousRequestError(RuntimeError):
    """Raised when a mutating request may have reached GitHub."""


class GitHubTransport:
    def __init__(
        self,
        token: str,
        *,
        opener: Callable[..., Any] = urlopen,
        sleep: Callable[[int], None] = time.sleep,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise ValueError("GitHub token must not be empty")
        self._token = token
        self._opener = opener
        self._sleep = sleep
        self._api_url = api_url.rstrip("/")

    def get_json(self, path: str) -> object:
        request = self._request(path)
        for request_number in range(3):
            try:
                with self._opener(request, timeout=30) as response:
                    if response.status != 200:
                        raise RuntimeError(
                            f"GitHub read request returned HTTP {response.status}"
                        )
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as error:
                if error.code in TRANSIENT_STATUS and request_number < 2:
                    self._sleep(2**request_number)
                    continue
                raise RuntimeError(
                    f"GitHub read request returned HTTP {error.code}"
                ) from error
            except URLError as error:
                if request_number < 2:
                    self._sleep(2**request_number)
                    continue
                raise RuntimeError(
                    "GitHub read request failed after three attempts"
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
