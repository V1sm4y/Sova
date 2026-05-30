"""Interactive orchestration layer for Sova scanners."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Iterable
from typing import Any, TypeVar

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from sova.scanner.certs import resolve_certificates
from sova.scanner.external import default_wordlist_path, run_gobuster, run_nikto, run_nmap
from sova.scanner.fuzzer import DEFAULT_PATHS, fuzz_paths
from sova.scanner.http import detect_http_services
from sova.scanner.models import ExternalToolResult
from sova.scanner.ports import DEFAULT_PORTS, discover_ports
from sova.utils.logger import render_banner

T = TypeVar("T")


class SovaEngine:
    """Runs the metasploit-style interactive console."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.target: str | None = None
        self.cached_ports: list[int] = []

    def run(self) -> None:
        self.console.print(render_banner())
        self.console.print(
            Panel.fit(
                "[bold]Sova Console[/bold]\nType menu numbers to run diagnostics. "
                "Press Ctrl+C or choose Exit to leave.",
                border_style="cyan",
            )
        )

        try:
            while True:
                self._ensure_target()
                action = self._prompt_action()
                if action == "1":
                    self._run_cert_resolution()
                elif action == "2":
                    self._run_port_discovery()
                elif action == "3":
                    self._run_http_detection()
                elif action == "4":
                    self._run_path_fuzzing()
                elif action == "5":
                    self._run_nmap()
                elif action == "6":
                    self._run_gobuster()
                elif action == "7":
                    self._run_nikto()
                elif action == "8":
                    self._run_native_checks()
                elif action == "9":
                    self._run_external_stack()
                elif action == "10":
                    self.target = None
                    self.cached_ports = []
                elif action == "11":
                    self.console.print("[bold green]Goodbye from Sova.[/bold green]")
                    return
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]Interrupted. Session closed.[/bold yellow]")

    def _ensure_target(self) -> None:
        while not self.target:
            target = Prompt.ask("[bold cyan]Target IP or domain[/bold cyan]", default="")
            if target.strip():
                self.target = target.strip()
                return
            self.console.print("[yellow]Target cannot be empty.[/yellow]")

    def _prompt_action(self) -> str:
        table = Table(title=f"Diagnostics for {self.target}", show_header=True)
        table.add_column("#", justify="right", style="cyan", no_wrap=True)
        table.add_column("Task", style="white")
        table.add_row("1", "Passive Certificate Resolution")
        table.add_row("2", "Asynchronous Port Discovery")
        table.add_row("3", "HTTP Service Detection")
        table.add_row("4", "Path Fuzzing")
        table.add_row("5", "Nmap Service Scan")
        table.add_row("6", "Gobuster Directory Scan")
        table.add_row("7", "Nikto Web Audit")
        table.add_row("8", "Run Native Python Checks")
        table.add_row("9", "Run External Tool Stack")
        table.add_row("10", "Change Target")
        table.add_row("11", "Exit")
        self.console.print(table)

        while True:
            choice = Prompt.ask("Select task", default="8").strip()
            if choice in {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}:
                return choice
            self.console.print("[yellow]Choose a number from 1 to 11.[/yellow]")

    def _prompt_ports(self, *, require_open: bool = False) -> list[int]:
        if self.cached_ports:
            reuse = Confirm.ask(
                f"Reuse cached ports {','.join(map(str, self.cached_ports))}?",
                default=True,
            )
            if reuse:
                return self.cached_ports

        default_ports = self.cached_ports if require_open and self.cached_ports else DEFAULT_PORTS
        raw_ports = Prompt.ask(
            "Ports, comma-separated",
            default=",".join(str(port) for port in default_ports),
        )
        ports = parse_ports(raw_ports)
        if not ports:
            ports = list(default_ports)
        return ports

    def _run_cert_resolution(self) -> None:
        if not self.target:
            return
        names = self._run_async(
            "Querying certificate transparency logs",
            resolve_certificates(self.target),
        )
        if not names:
            self.console.print("[yellow]No certificate names found.[/yellow]")
            return

        table = Table(title="Certificate Resolution", show_lines=False)
        table.add_column("Subdomain", style="green")
        for name in names:
            table.add_row(name)
        self.console.print(table)

    def _run_port_discovery(self) -> list[int]:
        if not self.target:
            return []
        ports = self._prompt_ports()
        results = self._run_async(
            "Checking ports asynchronously",
            discover_ports(self.target, ports),
        )
        self.cached_ports = [result.port for result in results if result.open]

        table = Table(title="Port Discovery")
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("State")
        for result in results:
            state = "[green]open[/green]" if result.open else "[red]closed[/red]"
            table.add_row(str(result.port), state)
        self.console.print(table)
        return self.cached_ports

    def _run_http_detection(self) -> None:
        if not self.target:
            return
        ports = self._prompt_ports(require_open=True)
        services = self._run_async(
            "Probing HTTP services",
            detect_http_services(self.target, ports),
        )
        if not services:
            self.console.print("[yellow]No HTTP services detected.[/yellow]")
            return

        table = Table(title="HTTP Service Detection")
        table.add_column("URL", style="cyan")
        table.add_column("Status", justify="right")
        table.add_column("Server")
        table.add_column("Title")
        for service in services:
            table.add_row(
                service.url,
                str(service.status_code),
                service.server or "-",
                service.title or "-",
            )
        self.console.print(table)

    def _run_path_fuzzing(self) -> None:
        if not self.target:
            return
        ports = self._prompt_ports(require_open=True)
        raw_paths = Prompt.ask(
            "Paths, comma-separated",
            default=",".join(DEFAULT_PATHS),
        )
        paths = [path.strip() for path in raw_paths.split(",") if path.strip()] or DEFAULT_PATHS
        findings = self._run_async(
            "Fuzzing common paths",
            fuzz_paths(self.target, ports, paths),
        )
        if not findings:
            self.console.print("[yellow]No non-404 paths found.[/yellow]")
            return

        table = Table(title="Path Fuzzing")
        table.add_column("URL", style="cyan")
        table.add_column("Status", justify="right")
        table.add_column("Bytes", justify="right")
        for finding in findings:
            table.add_row(finding.url, str(finding.status_code), str(finding.content_length))
        self.console.print(table)

    def _run_native_checks(self) -> None:
        self._run_cert_resolution()
        open_ports = self._run_port_discovery()
        if open_ports:
            self._run_http_detection()
            self._run_path_fuzzing()
        else:
            self.console.print("[yellow]Skipping HTTP checks because no open ports were found.[/yellow]")

    def _run_nmap(self) -> None:
        if not self.target:
            return
        ports = self._prompt_ports()
        result = self._run_async("Running nmap service scan", run_nmap(self.target, ports))
        self._render_external_result(result)

    def _run_gobuster(self) -> None:
        if not self.target:
            return
        url = self._prompt_url()
        wordlist = Prompt.ask("Gobuster wordlist", default=default_wordlist_path()).strip()
        result = self._run_async("Running gobuster directory scan", run_gobuster(url, wordlist))
        self._render_external_result(result)

    def _run_nikto(self) -> None:
        if not self.target:
            return
        url = self._prompt_url()
        result = self._run_async("Running nikto web audit", run_nikto(url))
        self._render_external_result(result)

    def _run_external_stack(self) -> None:
        self._run_nmap()
        if Confirm.ask("Run web-focused external tools too?", default=True):
            self._run_gobuster()
            self._run_nikto()

    def _prompt_url(self) -> str:
        default_port = self.cached_ports[0] if self.cached_ports else 80
        default_url = f"http://{self.target}" if default_port == 80 else f"http://{self.target}:{default_port}"
        return Prompt.ask("Target URL", default=default_url).strip()

    def _render_external_result(self, result: ExternalToolResult) -> None:
        command = " ".join(result.command)
        if not result.available:
            self.console.print(Panel(result.error or "Tool unavailable.", title=result.tool, border_style="yellow"))
            return

        output = result.stdout.strip() or result.stderr.strip() or result.error or "No output."
        if len(output) > 6000:
            output = f"{output[:6000]}\n\n[output truncated]"
        title = f"{result.tool} exit={result.return_code}" if result.return_code is not None else result.tool
        self.console.print(Panel.fit(command, title="Command", border_style="dim"))
        self.console.print(Panel(output, title=title, border_style="cyan"))

    def _run_async(self, description: str, coroutine: Coroutine[Any, Any, T]) -> T:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(description, total=1)
            result = asyncio.run(coroutine)
            progress.update(task_id, advance=1)
            return result


def parse_ports(raw_ports: str | Iterable[str]) -> list[int]:
    """Parse comma-separated ports, silently ignoring invalid values."""
    if isinstance(raw_ports, str):
        parts = raw_ports.split(",")
    else:
        parts = list(raw_ports)

    ports: list[int] = []
    for part in parts:
        try:
            port = int(str(part).strip())
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports
