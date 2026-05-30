"""JSON and Markdown reporting helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


def _to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    if isinstance(value, tuple):
        return [_to_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _to_plain(item) for key, item in value.items()}
    return value


def write_json_report(path: str | Path, payload: Any) -> Path:
    output_path = Path(path)
    output_path.write_text(json.dumps(_to_plain(payload), indent=2), encoding="utf-8")
    return output_path


def write_markdown_report(path: str | Path, title: str, sections: dict[str, Any]) -> Path:
    output_path = Path(path)
    lines = [f"# {title}", ""]
    for section_name, payload in sections.items():
        lines.extend([f"## {section_name}", ""])
        plain = _to_plain(payload)
        if isinstance(plain, list):
            if not plain:
                lines.extend(["No findings.", ""])
                continue
            for item in plain:
                lines.extend([f"- `{json.dumps(item, sort_keys=True)}`"])
        else:
            lines.extend(["```json", json.dumps(plain, indent=2), "```"])
        lines.append("")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
