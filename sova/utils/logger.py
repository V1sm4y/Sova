"""Rich rendering helpers."""

from __future__ import annotations

from rich.text import Text


def render_banner() -> Text:
    banner = r"""
   _____
  / ___/____ _   ______ _
  \__ \/ __ \ | / / __ `/
 ___/ / /_/ / |/ / /_/ /
/____/\____/|___/\__,_/
"""
    text = Text(banner, style="bold cyan")
    text.append("  Network diagnostics and service auditing\n", style="dim")
    return text
