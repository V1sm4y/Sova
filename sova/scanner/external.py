"""Optional wrappers for external recon tools."""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Iterable
from importlib import resources
from pathlib import Path

from sova.scanner.models import ExternalToolResult


def find_tool(tool: str) -> str | None:
    return shutil.which(tool)


def default_wordlist_path() -> str:
    wordlist = resources.files("sova").joinpath("wordlists/common.txt")
    return str(wordlist)


def build_nmap_command(target: str, ports: Iterable[int] | None = None) -> list[str]:
    command = ["nmap", "-sV", "-Pn"]
    if ports:
        command.extend(["-p", ",".join(str(port) for port in ports)])
    command.append(target)
    return command


def build_gobuster_command(url: str, wordlist: str | Path | None = None) -> list[str]:
    return [
        "gobuster",
        "dir",
        "-u",
        url,
        "-w",
        str(wordlist or default_wordlist_path()),
        "-q",
    ]


def build_nikto_command(url: str) -> list[str]:
    return ["nikto", "-h", url]


async def run_external_tool(
    tool: str,
    command: list[str],
    timeout: float = 120.0,
) -> ExternalToolResult:
    executable = find_tool(tool)
    if executable is None:
        return ExternalToolResult(
            tool=tool,
            available=False,
            command=command,
            return_code=None,
            stdout="",
            stderr="",
            error=f"{tool} is not installed or is not on PATH.",
        )

    resolved_command = [executable, *command[1:]]
    try:
        process = await asyncio.create_subprocess_exec(
            *resolved_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return ExternalToolResult(
            tool=tool,
            available=True,
            command=resolved_command,
            return_code=None,
            stdout="",
            stderr="",
            error=f"{tool} timed out after {timeout:.0f} seconds.",
        )
    except OSError as exc:
        return ExternalToolResult(
            tool=tool,
            available=True,
            command=resolved_command,
            return_code=None,
            stdout="",
            stderr="",
            error=str(exc),
        )

    return ExternalToolResult(
        tool=tool,
        available=True,
        command=resolved_command,
        return_code=process.returncode,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )


async def run_nmap(target: str, ports: Iterable[int] | None = None, timeout: float = 180.0) -> ExternalToolResult:
    return await run_external_tool("nmap", build_nmap_command(target, ports), timeout=timeout)


async def run_gobuster(
    url: str,
    wordlist: str | Path | None = None,
    timeout: float = 180.0,
) -> ExternalToolResult:
    return await run_external_tool("gobuster", build_gobuster_command(url, wordlist), timeout=timeout)


async def run_nikto(url: str, timeout: float = 180.0) -> ExternalToolResult:
    return await run_external_tool("nikto", build_nikto_command(url), timeout=timeout)
