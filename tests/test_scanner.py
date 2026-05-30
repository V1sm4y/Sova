from __future__ import annotations

import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sova import nmap_scan, scan_http_services, scan_ports
from sova.engine import parse_ports
from sova.scanner.external import (
    build_gobuster_command,
    build_nikto_command,
    build_nmap_command,
    run_external_tool,
)
from sova.scanner.fuzzer import fuzz_paths
from sova.scanner.http import detect_http_services, extract_title
from sova.scanner.ports import discover_ports


class MockHandler(BaseHTTPRequestHandler):
    server_version = "SovaMock/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path == "/missing":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return

        status = 200 if self.path in {"/", "/admin"} else 204
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Sova-Test", "true")
        self.end_headers()
        if status == 200:
            self.wfile.write(b"<html><head><title>Sova Mock Service</title></head><body>ok</body></html>")

    def log_message(self, format: str, *args: object) -> None:
        return


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_mock_server() -> tuple[ThreadingHTTPServer, int]:
    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_extract_title_normalizes_html_title() -> None:
    assert extract_title("<title> Sova &amp; Friends </title>") == "Sova & Friends"


def test_parse_ports_ignores_invalid_entries() -> None:
    assert parse_ports("80, nope,443,70000,80, 8080") == [80, 443, 8080]


def test_port_discovery_identifies_open_mock_server() -> None:
    server, port = start_mock_server()
    try:
        results = asyncio.run(discover_ports("127.0.0.1", [port], timeout=1.0))
        assert results[0].port == port
        assert results[0].open is True
    finally:
        server.shutdown()
        server.server_close()


def test_http_detection_reads_headers_and_title() -> None:
    server, port = start_mock_server()
    try:
        services = asyncio.run(detect_http_services("127.0.0.1", [port], timeout=2.0))
        assert len(services) == 1
        service = services[0]
        assert service.status_code == 200
        assert service.title == "Sova Mock Service"
        assert "SovaMock/1.0" in (service.server or "")
        assert service.headers["x-sova-test"] == "true"
    finally:
        server.shutdown()
        server.server_close()


def test_path_fuzzing_returns_non_404_paths_only() -> None:
    server, port = start_mock_server()
    try:
        findings = asyncio.run(
            fuzz_paths("127.0.0.1", [port], ["/admin", "/missing"], timeout=2.0)
        )
        assert [finding.path for finding in findings] == ["/admin"]
        assert findings[0].status_code == 200
    finally:
        server.shutdown()
        server.server_close()


def test_public_python_api_can_scan_mock_service() -> None:
    server, port = start_mock_server()
    try:
        port_results = asyncio.run(scan_ports("127.0.0.1", [port], timeout=1.0))
        assert port_results[0].open is True

        services = asyncio.run(scan_http_services("127.0.0.1", [port], timeout=2.0))
        assert services[0].title == "Sova Mock Service"
    finally:
        server.shutdown()
        server.server_close()


def test_external_tool_command_builders() -> None:
    assert build_nmap_command("example.com", [80, 443]) == [
        "nmap",
        "-sV",
        "-Pn",
        "-p",
        "80,443",
        "example.com",
    ]
    assert build_gobuster_command("http://example.com", "words.txt") == [
        "gobuster",
        "dir",
        "-u",
        "http://example.com",
        "-w",
        "words.txt",
        "-q",
    ]
    assert build_nikto_command("http://example.com") == ["nikto", "-h", "http://example.com"]


def test_missing_external_tool_returns_clean_result() -> None:
    result = asyncio.run(run_external_tool("definitely-not-a-real-sova-tool", ["missing-tool"]))
    assert result.available is False
    assert result.return_code is None
    assert "not installed" in (result.error or "")


def test_public_api_exposes_nmap_wrapper() -> None:
    assert callable(nmap_scan)
