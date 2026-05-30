"""Passive certificate transparency resolution through crt.sh."""

from __future__ import annotations

import httpx


def _normalize_name(name: str) -> list[str]:
    values: list[str] = []
    for item in name.splitlines():
        cleaned = item.strip().lower().lstrip("*.").rstrip(".")
        if cleaned and cleaned not in values:
            values.append(cleaned)
    return values


async def resolve_certificates(domain: str, timeout: float = 10.0, limit: int = 100) -> list[str]:
    """Query crt.sh for names observed in certificate transparency logs."""
    domain = domain.strip().lower().lstrip("*.").rstrip(".")
    if not domain:
        return []

    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            rows = response.json()
    except (httpx.HTTPError, ValueError):
        return []

    names: list[str] = []
    for row in rows:
        for field in ("name_value", "common_name"):
            raw_value = row.get(field) if isinstance(row, dict) else None
            if not raw_value:
                continue
            for name in _normalize_name(str(raw_value)):
                if name.endswith(domain) and name not in names:
                    names.append(name)
                if len(names) >= limit:
                    return sorted(names)
    return sorted(names)
