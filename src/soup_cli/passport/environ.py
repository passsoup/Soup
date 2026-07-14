"""Capture the runtime environment for the training record (spec block 3).

Everything here is best-effort and *offline*: we read versions already installed
and query the local GPU if torch happens to be present. Nothing is fetched. When
a fact cannot be determined we record ``null`` rather than guessing — an honest
gap, per Rule §3.
"""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from typing import Any, Optional

# Libraries whose versions matter for reproducing a fine-tune. Absent ones are
# simply omitted (light installs won't have torch/transformers).
_TRACKED_LIBS = (
    "torch",
    "transformers",
    "peft",
    "trl",
    "datasets",
    "accelerate",
    "bitsandbytes",
    "cryptography",
)


def _lib_version(name: str) -> Optional[str]:
    try:
        mod = __import__(name)
    except Exception:  # noqa: BLE001 — a broken optional dep must not crash capture
        return None
    return getattr(mod, "__version__", None)


def capture_libraries() -> dict[str, str]:
    """Return ``{lib: version}`` for the tracked libraries that are installed."""
    out: dict[str, str] = {}
    for name in _TRACKED_LIBS:
        v = _lib_version(name)
        if v:
            out[name] = v
    return out


def capture_hardware() -> dict[str, Any]:
    """Best-effort local hardware facts (GPU via torch if present, else CPU/RAM)."""
    gpu: Optional[str] = None
    ram_gb: Optional[float] = None
    cuda: Optional[str] = None
    try:
        import torch

        cuda = getattr(torch.version, "cuda", None)
        if torch.cuda.is_available():
            gpu = torch.cuda.get_device_name(0)
    except Exception:  # noqa: BLE001
        pass
    try:
        # os.sysconf is POSIX-only; guarded so Windows just records null.
        import os

        if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names:
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            ram_gb = round(pages * page_size / (1024**3), 1)
    except (ValueError, OSError, AttributeError):
        pass
    return {"gpu": gpu, "ram_gb": ram_gb, "cpu": platform.processor() or None, "cuda": cuda}


def capture_environment() -> dict[str, Any]:
    """Full environment snapshot for ``run.json`` / the training record block."""
    hw = capture_hardware()
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cuda": hw.get("cuda"),
        "libraries": capture_libraries(),
        "hardware": {k: hw.get(k) for k in ("gpu", "ram_gb", "cpu")},
    }


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string (from the system clock, spec §02)."""
    return datetime.now(tz=timezone.utc).isoformat()
