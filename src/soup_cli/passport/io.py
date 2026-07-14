"""Load/save passport JSON files (cwd-contained, symlink-safe, size-capped)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from soup_cli.passport.hashing import canonical_json
from soup_cli.utils.paths import atomic_write_text, enforce_under_cwd_and_no_symlink

_MAX_PASSPORT_BYTES = 32 * 1024 * 1024  # 32 MiB — a passport is small


def load_passport(path: str) -> dict[str, Any]:
    """Read + parse a passport JSON. Raises ValueError on bad path/shape."""
    real = enforce_under_cwd_and_no_symlink(path, "passport")
    p = Path(real)
    if not p.is_file():
        raise FileNotFoundError(f"passport not found: {path}")
    if p.stat().st_size > _MAX_PASSPORT_BYTES:
        raise ValueError(f"passport exceeds {_MAX_PASSPORT_BYTES} bytes")
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("passport must be a JSON object")
    return data


def save_passport(passport: dict[str, Any], path: str, *, canonical: bool = True) -> str:
    """Write a passport. Canonical form by default (byte-stable for verify)."""
    if canonical:
        text = canonical_json(passport)
    else:
        text = json.dumps(passport, indent=2, sort_keys=True, ensure_ascii=False)
    return atomic_write_text(text, path, prefix=".passport.", suffix=".json.tmp")
