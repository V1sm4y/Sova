"""Command-line entry point for Sova."""

from __future__ import annotations

import argparse
from typing import Sequence

from rich.console import Console

from sova import __version__
from sova.engine import SovaEngine
from sova.utils.logger import render_banner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sova",
        description="Sova - interactive network diagnostic and service auditing CLI.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    subparsers.add_parser("help", help="Show this help menu.")
    subparsers.add_parser("run", help="Start the interactive Sova console.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    console = Console()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command in (None, "help"):
        console.print(render_banner())
        parser.print_help()
        return 0

    if args.command == "run":
        engine = SovaEngine(console=console)
        engine.run()
        return 0

    parser.print_help()
    return 1
