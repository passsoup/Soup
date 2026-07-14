"""The Soup Model Passport — structure, assembly, and hash-chain (spec §1).

A passport is a plain ``dict`` (so it serialises to canonical JSON trivially and
stays language-agnostic for the web verifier). This module owns:

- the seven-block layout and the two provenance classes,
- ``build_hash_chain`` — the per-block + root digest that makes tampering
  self-evident,
- ``assemble_passport`` — glue the blocks + metadata into an *unsigned* passport,
- ``recompute_hash_chain`` / ``verify_hash_chain`` — the read side used by
  ``soup verify`` and the registry,
- ``validate_structure`` — cheap shape checks with human-readable messages.

Signing lives in :mod:`soup_cli.passport.crypto`; this file never touches keys.
"""

from __future__ import annotations

from typing import Any, Optional

from soup_cli.passport.hashing import hash_obj

PASSPORT_VERSION = "1.0"

PROVENANCE_NATIVE = "native"
PROVENANCE_ATTESTED = "attested"
PROVENANCE_CLASSES = (PROVENANCE_NATIVE, PROVENANCE_ATTESTED)

# The seven blocks, in their canonical order (spec §1.1). ``block_hashes`` is a
# sorted dict so order here is documentation, not a hashing dependency.
BLOCK_ORDER = (
    "identity",
    "data_provenance",
    "training_record",
    "evaluation",
    "security",
    "accountability",
    "lineage",
)


def empty_blocks() -> dict[str, dict]:
    """Return the seven blocks with honest, evidence-free defaults.

    Every field that cannot be substantiated yet is either absent or marked
    ``unattested`` — we never invent evidence (Rule §3, and spec §7).
    """
    return {
        "identity": {
            "base_model": {
                "name": None,
                "hash": None,
                "license": None,
                "derivative_obligations": [],
            },
        },
        "data_provenance": {
            "datasets": [],
            "pii_scan": {"status": "unattested", "details": ""},
            "origin_legality": "unattested",
        },
        "training_record": {
            "method": None,
            "hyperparameters": {},
            "hardware": {"gpu": None, "ram_gb": None},
            "duration_seconds": None,
            "environment": {"python": None, "cuda": None, "libraries": {}},
        },
        "evaluation": {
            "scores": {},
            "gate_verdict": None,
            "gate_reasons": [],
        },
        "security": {
            "integrity": "unattested",
            "backdoor_scan": {"status": "unattested", "findings": []},
        },
        "accountability": {
            "run_by": None,
            "signed_at": None,
            "signer": {"type": None, "label": None, "public_key": None},
        },
        "lineage": {
            "parent_passport_hash": None,
            "version_history": [],
            "diff_from_parent": {},
        },
    }


def build_hash_chain(blocks: dict[str, Any]) -> dict[str, Any]:
    """Compute ``{"block_hashes": {...}, "root_hash": ...}`` for ``blocks``.

    ``block_hashes[b] = hash_obj(blocks[b])`` and
    ``root_hash = hash_obj(block_hashes)``. Because ``hash_obj`` canonicalises
    (sorted keys, no whitespace), flipping any byte in any block changes that
    block's hash, which changes ``root_hash``, which breaks the signature.
    """
    block_hashes = {name: hash_obj(body) for name, body in blocks.items()}
    root_hash = hash_obj(block_hashes)
    return {"block_hashes": block_hashes, "root_hash": root_hash}


def assemble_passport(
    *,
    model_name: str,
    model_version: str,
    created_at: str,
    blocks: dict[str, Any],
    provenance_class: str = PROVENANCE_NATIVE,
    unattested_fields: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Build an **unsigned** passport dict with a fresh hash chain.

    The caller signs it afterwards (``crypto.sign_passport``). ``blocks`` is
    used as-is (already merged with :func:`empty_blocks` by the builder), so the
    hash chain covers exactly what ends up on disk.
    """
    if provenance_class not in PROVENANCE_CLASSES:
        raise ValueError(
            f"provenance_class must be one of {PROVENANCE_CLASSES}, got {provenance_class!r}"
        )
    passport = {
        "soup_passport_version": PASSPORT_VERSION,
        "provenance_class": provenance_class,
        "model": {
            "name": model_name,
            "version": model_version,
            "created_at": created_at,
        },
        "blocks": blocks,
        "unattested_fields": sorted(set(unattested_fields or [])),
        "hash_chain": build_hash_chain(blocks),
    }
    return passport


def recompute_hash_chain(passport: dict[str, Any]) -> dict[str, Any]:
    """Recompute the hash chain from ``passport["blocks"]`` (read side)."""
    blocks = passport.get("blocks")
    if not isinstance(blocks, dict):
        raise ValueError("passport has no 'blocks' object")
    return build_hash_chain(blocks)


def verify_hash_chain(passport: dict[str, Any]) -> tuple[bool, list[str]]:
    """Check the passport's stored hash chain against a fresh recomputation.

    Returns ``(ok, problems)``. ``problems`` names each block whose stored hash
    no longer matches its content, plus a root-hash mismatch if present — this
    is what ``soup verify`` prints to say *which* block was altered.
    """
    problems: list[str] = []
    stored = passport.get("hash_chain")
    if not isinstance(stored, dict):
        return False, ["passport has no 'hash_chain'"]
    recomputed = recompute_hash_chain(passport)

    stored_bh = stored.get("block_hashes", {})
    recomputed_bh = recomputed["block_hashes"]
    if not isinstance(stored_bh, dict):
        return False, ["hash_chain.block_hashes is not an object"]

    for name in sorted(set(stored_bh) | set(recomputed_bh)):
        if name not in stored_bh:
            problems.append(f"block '{name}' missing from stored block_hashes")
        elif name not in recomputed_bh:
            problems.append(f"unexpected block '{name}' in stored block_hashes")
        elif stored_bh[name] != recomputed_bh[name]:
            problems.append(f"block '{name}' was altered (hash mismatch)")

    if stored.get("root_hash") != recomputed["root_hash"]:
        problems.append("root_hash mismatch")

    return (not problems), problems


def validate_structure(passport: Any) -> list[str]:
    """Cheap structural validation; returns a list of human-readable problems.

    Empty list == well-formed enough to verify. This is not a JSON-Schema
    validator — it catches the mistakes that would make ``verify`` crash rather
    than fail cleanly.
    """
    problems: list[str] = []
    if not isinstance(passport, dict):
        return ["passport is not a JSON object"]
    if passport.get("soup_passport_version") != PASSPORT_VERSION:
        problems.append(
            f"unsupported soup_passport_version "
            f"{passport.get('soup_passport_version')!r} (expected {PASSPORT_VERSION!r})"
        )
    if passport.get("provenance_class") not in PROVENANCE_CLASSES:
        problems.append(
            f"provenance_class must be one of {PROVENANCE_CLASSES}"
        )
    if not isinstance(passport.get("model"), dict):
        problems.append("missing 'model' object")
    if not isinstance(passport.get("blocks"), dict):
        problems.append("missing 'blocks' object")
    if not isinstance(passport.get("hash_chain"), dict):
        problems.append("missing 'hash_chain' object")
    return problems
