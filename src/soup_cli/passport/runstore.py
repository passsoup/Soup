"""The ``.soup/`` run directory — working memory between pipeline commands (spec §02).

Each free-core command drops a small JSON of *evidence* here; ``soup passport``
later folds those files into the seven blocks. Nothing secret lands in the run
dir — only hashes, scores, and environment facts — so it is safe to commit to a
repo or attach to a CI artifact.

Layout::

    .soup/
      run.json        # run id, timestamps, captured environment
      train.json      # training record  -> block 3
      eval.json       # eval scores + regressions -> block 4
      gate.json       # SHIP / DON'T SHIP verdict -> block 4
      scan.json       # integrity + backdoor scan -> block 5
      dataset.json    # dataset fingerprints -> block 2
      artifacts/      # checkpoint hashes

Writes are atomic (temp file + ``os.replace``) and refuse to follow a symlink at
the destination, mirroring the repo's TOCTOU policy in ``utils/paths.py``. The
run dir is operator-supplied (``--run-dir``) so it is the containment boundary;
we do not additionally force it under cwd (that would break ``--run-dir /tmp/x``).
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Optional

DEFAULT_RUN_DIR = ".soup"

# Canonical evidence file names.
RUN = "run.json"
TRAIN = "train.json"
EVAL = "eval.json"
GATE = "gate.json"
SCAN = "scan.json"
DATASET = "dataset.json"

_MAX_READ_BYTES = 64 * 1024 * 1024  # 64 MiB — generous for JSON evidence


def _atomic_write_json(target: Path, data: Any) -> None:
    """Atomic JSON write that refuses to overwrite through a symlink."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        st = os.lstat(target)
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"{target.name!r} must not be a symlink (TOCTOU defence)")
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    fd, tmp = tempfile.mkstemp(prefix=".soup-run.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


class RunStore:
    """Read/write the JSON evidence files under a run directory."""

    def __init__(self, run_dir: str | Path = DEFAULT_RUN_DIR) -> None:
        self.root = Path(run_dir)

    # -- paths ------------------------------------------------------------- #
    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    def path(self, name: str) -> Path:
        return self.root / name

    def exists(self, name: str) -> bool:
        return self.path(name).is_file()

    # -- generic read/write ------------------------------------------------ #
    def write(self, name: str, data: Any) -> Path:
        target = self.path(name)
        _atomic_write_json(target, data)
        return target

    def read(self, name: str) -> dict:
        target = self.path(name)
        if not target.is_file():
            raise FileNotFoundError(f"{name} not found in run dir {self.root}")
        if target.stat().st_size > _MAX_READ_BYTES:
            raise ValueError(f"{name} exceeds {_MAX_READ_BYTES} bytes")
        with target.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"{name} must contain a JSON object")
        return data

    def read_optional(self, name: str) -> Optional[dict]:
        """Read ``name`` if present and well-formed, else ``None`` (never raises)."""
        try:
            return self.read(name)
        except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError):
            return None

    # -- run lifecycle ----------------------------------------------------- #
    def init_run(self, run_id: str, created_at: str, environment: dict) -> dict:
        """Create/refresh ``run.json`` with run metadata + captured environment."""
        record = {
            "run_id": run_id,
            "created_at": created_at,
            "environment": environment,
        }
        self.write(RUN, record)
        return record

    def ensure_run(self, run_id: str, created_at: str, environment: dict) -> dict:
        """Return the existing run.json, or create one if absent."""
        existing = self.read_optional(RUN)
        if existing:
            return existing
        return self.init_run(run_id, created_at, environment)
