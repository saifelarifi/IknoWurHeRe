"""Offline IEEE OUI lookup from an optional user-provided CSV registry."""

from __future__ import annotations

import csv
import os
import re
from functools import lru_cache
from pathlib import Path

from .database import default_database_path


def default_oui_path() -> Path:
    return Path(os.environ.get("IKNOWURHERE_OUI_FILE", default_database_path().parent / "oui.csv")).expanduser()


@lru_cache(maxsize=2)
def _load_registry(path_text: str, modified_ns: int, size: int) -> dict[str, str]:
    del modified_ns, size  # Included in the cache key to reload after registry updates.
    path = Path(path_text)
    registry: dict[str, str] = {}
    try:
        with path.open(newline="", encoding="utf-8-sig") as source:
            reader = csv.DictReader(source)
            for row in reader:
                assignment = row.get("Assignment") or row.get("assignment") or ""
                organization = row.get("Organization Name") or row.get("Organization") or ""
                prefix = re.sub(r"[^0-9a-fA-F]", "", assignment).upper()
                if len(prefix) in {6, 7, 9} and organization.strip():
                    registry[prefix] = organization.strip()
    except (OSError, UnicodeError, csv.Error):
        return {}
    return registry


def lookup_vendor(mac: str | None, *, path: str | Path | None = None) -> str | None:
    """Return an offline vendor label when the optional IEEE CSV is installed."""
    if not mac:
        return None
    registry_path = Path(path).expanduser() if path else default_oui_path()
    try:
        stat = registry_path.stat()
    except OSError:
        return None
    registry = _load_registry(str(registry_path), stat.st_mtime_ns, stat.st_size)
    compact_mac = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    for prefix_length in (9, 7, 6):
        if len(compact_mac) >= prefix_length and compact_mac[:prefix_length] in registry:
            return registry[compact_mac[:prefix_length]]
    return None
