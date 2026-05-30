"""Shared scanner result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    open: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HttpService:
    host: str
    port: int
    scheme: str
    url: str
    status_code: int
    title: str | None
    server: str | None
    headers: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FuzzResult:
    host: str
    port: int
    scheme: str
    path: str
    url: str
    status_code: int
    content_length: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ExternalToolResult:
    tool: str
    available: bool
    command: list[str]
    return_code: int | None
    stdout: str
    stderr: str
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
