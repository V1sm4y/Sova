# Sova

Sova is a professional-grade command-line network diagnostic and service
auditing tool. It is designed to work like a GitHub CLI project you can clone,
install, and run from the terminal, while still exposing a small Python API for
automation scripts and other tools.

## Clone And Install

```bash
git clone https://github.com/V1sm4y/Sova.git
cd Sova
pip install -e .
```

Editable install gives you the `sova` terminal command locally while keeping the
source tree easy to modify.

## CLI Usage

```bash
sova
sova help
sova run
```

## Features

- Passive certificate resolution through `crt.sh`
- Asynchronous TCP port discovery
- HTTP service detection with title and header extraction
- Path fuzzing for non-404 responses
- Optional external tool orchestration for `nmap`, `gobuster`, and `nikto`
- JSON and Markdown reporting helpers
- Pytest coverage with a local mock HTTP service

## Optional External Tools

Sova has native Python scanners, but it can also orchestrate common security
tools when they are installed and available on PATH.

```bash
nmap --version
gobuster version
nikto -Version
```

In the interactive menu:

- `5` runs an `nmap -sV -Pn` service scan
- `6` runs a `gobuster dir` directory scan
- `7` runs a `nikto` web audit
- `9` runs the external stack

If a tool is missing, Sova reports that cleanly instead of crashing.

## Python API Usage

Sova can also be imported from Python when you want to reuse the scanners
without opening the interactive CLI.

```python
import asyncio
from sova import nmap_scan, scan_http_services, scan_ports


async def main():
    ports = await scan_ports("127.0.0.1", [80, 8080])
    open_ports = [result.port for result in ports if result.open]
    services = await scan_http_services("127.0.0.1", open_ports)
    for service in services:
        print(service.url, service.status_code, service.title)

    nmap_result = await nmap_scan("127.0.0.1", [80, 8080])
    print(nmap_result.stdout or nmap_result.error)


asyncio.run(main())
```

## Tests

```bash
pytest
```
