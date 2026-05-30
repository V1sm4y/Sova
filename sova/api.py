"""Public Python API for embedding Sova scanners in other tools."""

from __future__ import annotations

from collections.abc import Iterable

from sova.scanner.certs import resolve_certificates
from sova.scanner.external import run_gobuster, run_nikto, run_nmap
from sova.scanner.fuzzer import DEFAULT_PATHS, fuzz_paths
from sova.scanner.http import detect_http_services
from sova.scanner.models import ExternalToolResult, FuzzResult, HttpService, PortResult
from sova.scanner.ports import DEFAULT_PORTS, discover_ports


async def scan_ports(
    host: str,
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout: float = 1.5,
) -> list[PortResult]:
    return await discover_ports(host, ports, timeout=timeout)


async def scan_http_services(
    host: str,
    ports: Iterable[int],
    timeout: float = 3.0,
) -> list[HttpService]:
    return await detect_http_services(host, ports, timeout=timeout)


async def scan_paths(
    host: str,
    ports: Iterable[int],
    paths: Iterable[str] = DEFAULT_PATHS,
    timeout: float = 3.0,
) -> list[FuzzResult]:
    return await fuzz_paths(host, ports, paths, timeout=timeout)


async def scan_certificates(
    domain: str,
    timeout: float = 10.0,
    limit: int = 100,
) -> list[str]:
    return await resolve_certificates(domain, timeout=timeout, limit=limit)


async def nmap_scan(
    target: str,
    ports: Iterable[int] | None = None,
    timeout: float = 180.0,
) -> ExternalToolResult:
    return await run_nmap(target, ports, timeout=timeout)


async def gobuster_scan(
    url: str,
    wordlist: str | None = None,
    timeout: float = 180.0,
) -> ExternalToolResult:
    return await run_gobuster(url, wordlist, timeout=timeout)


async def nikto_scan(url: str, timeout: float = 180.0) -> ExternalToolResult:
    return await run_nikto(url, timeout=timeout)
