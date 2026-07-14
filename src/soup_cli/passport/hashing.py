"""Canonical hashing for the Soup Model Passport (Passport spec §1.4).

The passport's whole security story rests on one property: **the same passport
always produces the same bytes, and therefore the same hash.** If canonicalisation
drifts between the writer (``soup passport``) and any reader (``soup verify``,
the ``/verify`` web page, the registry), a valid passport would read as tampered.

So this module is deliberately tiny and dependency-free (stdlib only) and is the
*single source of truth* for:

- ``canonical_json(obj)`` — deterministic UTF-8 JSON (sorted keys, no spaces).
- ``sha256_hex(data)`` — ``sha256:``-prefixed hex digest, matching the passport
  schema's ``"sha256:..."`` convention.
- ``hash_obj(obj)`` — canonicalise then hash (the block-hash primitive).
- ``hash_file(path)`` — streamed file digest for artifact fingerprints.

The canonical form is exactly the one written in the spec:
``json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)``.
Do not "improve" it — the web verifier reimplements the same rule in JS.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_HASH_CHUNK_BYTES = 1024 * 1024  # 1 MiB streaming window for large weight files
_SHA256_PREFIX = "sha256:"


def canonical_json(obj: Any) -> str:
    """Serialise ``obj`` to the one canonical JSON string used everywhere.

    Sorted keys, no insignificant whitespace, UTF-8 (``ensure_ascii=False`` so
    non-ASCII text hashes identically to how a human sees it). This exact call
    is mirrored byte-for-byte by the ``/verify`` browser implementation.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_bytes(obj: Any) -> bytes:
    """UTF-8 bytes of :func:`canonical_json` — the thing that actually gets hashed."""
    return canonical_json(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return ``sha256:<hex>`` for ``data`` (matches the passport hash convention)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    return _SHA256_PREFIX + hashlib.sha256(bytes(data)).hexdigest()


def hash_obj(obj: Any) -> str:
    """Canonicalise ``obj`` and return its ``sha256:`` digest.

    This is the block-hash primitive: ``block_hashes[b] = hash_obj(blocks[b])``
    and ``root_hash = hash_obj(block_hashes)``.
    """
    return sha256_hex(canonical_bytes(obj))


def hash_file(path: str | Path) -> str:
    """Stream a file through SHA-256; return ``sha256:<hex>``.

    Streamed in 1 MiB chunks so multi-GB checkpoints never need to fit in RAM.
    Raises ``FileNotFoundError`` if the path is missing or not a regular file.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return _SHA256_PREFIX + digest.hexdigest()


def hash_dir(path: str | Path) -> str:
    """Deterministic digest of a directory tree (relative-path + content).

    Walks the tree in sorted relative-path order and folds each file's path and
    content digest into one rolling SHA-256. Two directories with identical file
    layout and bytes produce the same digest regardless of walk order or mtime.
    Used to fingerprint a whole checkpoint folder (weights + tokenizer + config).
    """
    root = Path(path)
    if root.is_file():
        return hash_file(root)
    if not root.is_dir():
        raise FileNotFoundError(f"directory not found: {path}")
    digest = hashlib.sha256()
    files = sorted(
        (p for p in root.rglob("*") if p.is_file() and not p.is_symlink()),
        key=lambda p: p.relative_to(root).as_posix(),
    )
    for p in files:
        rel = p.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        # Reuse the streamed file digest (hex, without prefix) as the leaf.
        digest.update(hash_file(p).encode("ascii"))
        digest.update(b"\n")
    return _SHA256_PREFIX + digest.hexdigest()
