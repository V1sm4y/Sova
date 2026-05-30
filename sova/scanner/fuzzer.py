"""HTTP path fuzzing scanner."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

import httpx

from sova.scanner.http import candidate_urls
from sova.scanner.models import FuzzResult

DEFAULT_PATHS = ["/", "/admin", "/login", "/robots.txt", "/health", "/api"]


def normalize_path(path: str) -> str:
    path = path.strip()
    if not path:
        return "/"
    return path if path.startswith("/") else f"/{path}"


async def _fuzz_one(
    client: httpx.AsyncClient,
    host: str,
    port: int,
    path: str,
) -> FuzzResult | None:
    normalized = normalize_path(path)
    for scheme, base_url in candidate_urls(host, port):
        url = f"{base_url.rstrip('/')}{normalized}"
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            continue
        if response.status_code != 404:
            return FuzzResult(
                host=host,
                port=port,
                scheme=scheme,
                path=normalized,
                url=str(response.url),
                status_code=response.status_code,
                content_length=len(response.content),
            )
    return None


async def fuzz_paths(
    host: str,
    ports: Iterable[int],
    paths: Iterable[str] = DEFAULT_PATHS,
    timeout: float = 3.0,
    concurrency: int = 100,
) -> list[FuzzResult]:
    semaphore = asyncio.Semaphore(concurrency)
    unique_paths = list(dict.fromkeys(normalize_path(path) for path in paths))

    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
        async def guarded(port: int, path: str) -> FuzzResult | None:
            async with semaphore:
                return await _fuzz_one(client, host, port, path)

        tasks = [guarded(int(port), path) for port in ports for path in unique_paths]
        results = await asyncio.gather(*tasks)

    findings = [result for result in results if result is not None]
    return sorted(findings, key=lambda item: (item.port, item.path))
