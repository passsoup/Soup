"""Assemble a Model Passport from run evidence (spec `soup passport`, §1).

The builder is the honest historian: it reads whatever the free-core commands
left in ``.soup/`` (train / eval / gate / scan) and folds it into the seven
blocks. Where a piece of evidence is missing, the corresponding field stays at
its ``unattested`` default *and* is named in ``unattested_fields`` — we never
invent evidence to fill a gap (Rule §3).

Native vs Attested:

- ``native`` — this run was recorded inside Soup at training time; the chain is
  a "birth certificate" (``soup passport build``).
- ``attested`` — an external model onboarded via ``soup adopt``; only what can
  be re-checked after the fact is attested, the rest is ``unattested``.
"""

from __future__ import annotations

import getpass
import platform
from typing import Any, Optional

from soup_cli.passport.environ import capture_environment, utc_now_iso
from soup_cli.passport.hashing import hash_obj
from soup_cli.passport.runstore import RunStore
from soup_cli.passport.schema import (
    PROVENANCE_NATIVE,
    assemble_passport,
    empty_blocks,
)


def _run_by() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "unknown"
    return f"{user}@{platform.node() or 'unknown'}"


def build_blocks_from_run(
    store: RunStore,
    *,
    parent_passport: Optional[dict] = None,
) -> tuple[dict[str, Any], list[str]]:
    """Fold ``.soup/`` evidence into the seven blocks; return (blocks, unattested).

    ``unattested`` is the honest list of block-paths with no backing evidence.
    """
    blocks = empty_blocks()
    unattested: list[str] = []

    train = store.read_optional("train.json")
    eval_json = store.read_optional("eval.json")
    gate = store.read_optional("gate.json")
    scan = store.read_optional("scan.json")
    run = store.read_optional("run.json")

    # --- Block 1: identity (base model) ----------------------------------- #
    if train and isinstance(train.get("base_model"), dict):
        blocks["identity"]["base_model"] = train["base_model"]
    else:
        unattested.append("blocks.identity.base_model")

    # --- Block 2: data provenance ----------------------------------------- #
    if train and train.get("datasets"):
        blocks["data_provenance"]["datasets"] = train["datasets"]
    else:
        unattested.append("blocks.data_provenance.datasets")
    # PII scan / origin legality are not established by the free pipeline.
    unattested.append("blocks.data_provenance.pii_scan")
    unattested.append("blocks.data_provenance.origin_legality")

    # --- Block 3: training record ----------------------------------------- #
    if train:
        tr = blocks["training_record"]
        tr["method"] = train.get("method")
        tr["hyperparameters"] = train.get("hyperparameters", {})
        tr["hardware"] = train.get("hardware", tr["hardware"])
        tr["duration_seconds"] = train.get("duration_seconds")
        tr["environment"] = train.get("environment", tr["environment"])
    else:
        # No training evidence — capture at least the current environment so the
        # block is not empty, but mark it unattested (we didn't witness training).
        env = capture_environment()
        blocks["training_record"]["environment"] = {
            "python": env.get("python"),
            "cuda": env.get("cuda"),
            "libraries": env.get("libraries", {}),
        }
        unattested.append("blocks.training_record")

    # --- Block 4: evaluation ---------------------------------------------- #
    if eval_json and isinstance(eval_json.get("scores"), dict):
        blocks["evaluation"]["scores"] = eval_json["scores"]
    else:
        unattested.append("blocks.evaluation.scores")
    if gate:
        blocks["evaluation"]["gate_verdict"] = gate.get("gate_verdict")
        blocks["evaluation"]["gate_reasons"] = gate.get("gate_reasons", [])
    else:
        unattested.append("blocks.evaluation.gate_verdict")

    # --- Block 5: security ------------------------------------------------ #
    if scan:
        blocks["security"]["integrity"] = scan.get("integrity", "unattested")
        blocks["security"]["backdoor_scan"] = scan.get(
            "backdoor_scan", {"status": scan.get("status", "unattested"), "findings": []}
        )
    else:
        unattested.append("blocks.security")

    # --- Block 6: accountability ------------------------------------------ #
    blocks["accountability"]["run_by"] = _run_by()
    blocks["accountability"]["signed_at"] = utc_now_iso()
    # signer is filled by crypto.sign_passport.

    # --- Block 7: lineage ------------------------------------------------- #
    if parent_passport:
        blocks["lineage"]["parent_passport_hash"] = _passport_hash(parent_passport)
        blocks["lineage"]["diff_from_parent"] = _diff_from_parent(parent_passport, blocks)
        prev_history = parent_passport.get("blocks", {}).get("lineage", {}).get(
            "version_history", []
        )
        parent_model = parent_passport.get("model", {})
        blocks["lineage"]["version_history"] = list(prev_history) + [
            {
                "version": parent_model.get("version"),
                "passport_hash": blocks["lineage"]["parent_passport_hash"],
            }
        ]

    # If we have no training evidence but do have a recorded run environment,
    # prefer the run's captured environment over the just-captured one.
    if run and not train and isinstance(run.get("environment"), dict):
        env = run["environment"]
        blocks["training_record"]["environment"] = {
            "python": env.get("python"),
            "cuda": env.get("cuda"),
            "libraries": env.get("libraries", {}),
        }

    return blocks, sorted(set(unattested))


def _passport_hash(passport: dict) -> str:
    """Hash of a passport's root hash — a stable pointer for lineage."""
    root = passport.get("hash_chain", {}).get("root_hash")
    if root:
        return hash_obj({"root_hash": root})
    return hash_obj(passport.get("blocks", {}))


def _diff_from_parent(parent: dict, child_blocks: dict) -> dict:
    """A shallow diff of eval scores between parent and child (illustrative)."""
    parent_scores = parent.get("blocks", {}).get("evaluation", {}).get("scores", {})
    child_scores = child_blocks.get("evaluation", {}).get("scores", {})
    diff: dict[str, Any] = {}
    for task in sorted(set(parent_scores) | set(child_scores)):
        before = parent_scores.get(task, {}).get("after") if isinstance(
            parent_scores.get(task), dict
        ) else None
        after = child_scores.get(task, {}).get("after") if isinstance(
            child_scores.get(task), dict
        ) else None
        if before != after:
            diff[task] = {"before": before, "after": after}
    return diff


def build_passport(
    store: RunStore,
    *,
    model_name: str,
    model_version: str,
    provenance_class: str = PROVENANCE_NATIVE,
    parent_passport: Optional[dict] = None,
    created_at: Optional[str] = None,
) -> dict[str, Any]:
    """Build an **unsigned** passport from the run evidence."""
    blocks, unattested = build_blocks_from_run(store, parent_passport=parent_passport)
    return assemble_passport(
        model_name=model_name,
        model_version=model_version,
        created_at=created_at or utc_now_iso(),
        blocks=blocks,
        provenance_class=provenance_class,
        unattested_fields=unattested,
    )
