from __future__ import annotations

import json
from typing import Self
from urllib.request import Request


class FakeResponse:
    def __init__(self, status: int, payload: object | None = None) -> None:
        self.status = status
        self._body = b"" if payload is None else json.dumps(payload).encode()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class RecordingOpener:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests: list[Request] = []

    def __call__(self, request: Request, timeout: int) -> FakeResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        assert isinstance(response, FakeResponse)
        return response
