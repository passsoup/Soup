"""Training-record evidence (spec block 3) — captured at training time.

Real fine-tuning is the existing ``soup train`` (the free entry to the product).
This module builds the *evidence* that turns a finished checkpoint into passport
block 3: the base-model fingerprint, dataset fingerprints, method + hyper-params,
hardware, duration, and the exact environment. Raw data and weights are never
copied — only hashes.

``soup passport train`` calls :func:`build_training_record`; a future in-process
hook on ``soup train`` can call the same function so a native run drops
``.soup/train.json`` automatically.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from soup_cli.passport.environ import capture_environment
from soup_cli.passport.hashing import hash_dir, hash_file


def fingerprint_datasets(paths: list[str]) -> list[dict[str, Any]]:
    """Fingerprint dataset files/dirs: name, hash, size. Never copies the data."""
    out: list[dict[str, Any]] = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            out.append(
                {"name": raw, "hash": None, "source": raw, "size_bytes": None, "note": "not found"}
            )
            continue
        if p.is_dir():
            size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
            out.append({"name": p.name, "hash": hash_dir(p), "source": str(p), "size_bytes": size})
        else:
            out.append(
                {
                    "name": p.name,
                    "hash": hash_file(p),
                    "source": str(p),
                    "size_bytes": p.stat().st_size,
                }
            )
    return out


def fingerprint_base_model(base: str, *, license_name: Optional[str] = None,
                           derivative_obligations: Optional[list[str]] = None) -> dict[str, Any]:
    """Fingerprint the base model. A local path is hashed; a hub id is recorded by name.

    We do not fetch a hub model just to hash it (that would break the no-network
    rule); an un-hashable remote base is honestly recorded with ``hash: null``.
    """
    p = Path(base)
    if p.exists():
        model_hash = hash_dir(p) if p.is_dir() else hash_file(p)
    else:
        model_hash = None  # remote hub id — not fetched, honestly null
    return {
        "name": base,
        "hash": model_hash,
        "license": license_name,
        "derivative_obligations": list(derivative_obligations or []),
    }


def build_training_record(
    *,
    base_model: str,
    method: str,
    output_path: Optional[str] = None,
    datasets: Optional[list[str]] = None,
    hyperparameters: Optional[dict[str, Any]] = None,
    duration_seconds: Optional[float] = None,
    base_license: Optional[str] = None,
    derivative_obligations: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Assemble the ``train.json`` evidence dict (blocks 1, 2 and 3 material)."""
    env = capture_environment()
    record: dict[str, Any] = {
        "base_model": fingerprint_base_model(
            base_model, license_name=base_license, derivative_obligations=derivative_obligations
        ),
        "method": method,
        "hyperparameters": hyperparameters or {},
        "hardware": env.get("hardware", {}),
        "duration_seconds": duration_seconds,
        "environment": {
            "python": env.get("python"),
            "cuda": env.get("cuda"),
            "libraries": env.get("libraries", {}),
        },
        "datasets": fingerprint_datasets(datasets or []),
    }
    if output_path:
        p = Path(output_path)
        if p.exists():
            record["output_hash"] = hash_dir(p) if p.is_dir() else hash_file(p)
    return record
