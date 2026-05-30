"""HTTP service detection."""

from __future__ import annotations

import asyncio
import html
import re
from collections.abc import Iterable

import httpx

from sova.scanner.models import HttpService

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(body: str) -> str | None:
    match = TITLE_RE.search(body)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return html.unescape(title) if title else None


def candidate_urls(host: str, port: int) -> list[tuple[str, str]]:
    if port == 443:
        return [("https", f"https://{host}"), ("http", f"http://{host}:{port}")]
    if port == 80:
        return [("http", f"http://{host}"), ("https", f"https://{host}:{port}")]
    return [("http", f"http://{host}:{port}"), ("https", f"https://{host}:{port}")]


async def probe_http_service(
    host: str,
    port: int,
    timeout: float = 3.0,
    client: httpx.AsyncClient | None = None,
) -> HttpService | None:
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout)

    try:
        for scheme, url in candidate_urls(host, port):
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue
            title = extract_title(response.text)
            return HttpService(
                host=host,
                port=port,
                scheme=scheme,
                url=str(response.url),
                status_code=response.status_code,
                title=title,
                server=response.headers.get("server"),
                headers=dict(response.headers),
            )
        return None
    finally:
        if owns_client:
            await client.aclose()


async def detect_http_services(
    host: str,
    ports: Iterable[int],
    timeout: float = 3.0,
) -> list[HttpService]:
    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
        tasks = [probe_http_service(host, int(port), timeout=timeout, client=client) for port in ports]
        services = await asyncio.gather(*tasks)
    return [service for service in services if service is not None]
