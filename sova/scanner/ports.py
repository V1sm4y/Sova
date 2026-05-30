"""Asynchronous TCP port discovery."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterable

from sova.scanner.models import PortResult

DEFAULT_PORTS = [80, 443, 8080, 8443]


async def check_port(host: str, port: int, timeout: float = 1.5) -> PortResult:
    try:
        connection = asyncio.open_connection(host=host, port=port, family=socket.AF_UNSPEC)
        reader, writer = await asyncio.wait_for(connection, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return PortResult(host=host, port=port, open=True)
    except (asyncio.TimeoutError, OSError) as exc:
        return PortResult(host=host, port=port, open=False, error=str(exc) or exc.__class__.__name__)


async def discover_ports(
    host: str,
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout: float = 1.5,
    concurrency: int = 200,
) -> list[PortResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def guarded(port: int) -> PortResult:
        async with semaphore:
            return await check_port(host, port, timeout=timeout)

    unique_ports = list(dict.fromkeys(int(port) for port in ports))
    results = await asyncio.gather(*(guarded(port) for port in unique_ports))
    return sorted(results, key=lambda result: result.port)
