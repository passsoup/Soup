"""Phase 2 — passport assembly from run evidence + end-to-end verify."""

from __future__ import annotations

import pytest

from soup_cli.passport import crypto
from soup_cli.passport.builder import build_passport
from soup_cli.passport.runstore import RunStore

pytestmark = pytest.mark.unit

requires_crypto = pytest.mark.skipif(
    not crypto.is_available(), reason="cryptography not installed"
)


def _seed_run(tmp_path):
    store = RunStore(tmp_path / ".soup")
    store.write(
        "train.json",
        {
            "base_model": {"name": "tiny-llm", "hash": "sha256:abc", "license": "mit",
                           "derivative_obligations": []},
            "method": "lora",
            "hyperparameters": {"lr": 2e-5},
            "hardware": {"gpu": None, "ram_gb": 8},
            "duration_seconds": 42,
            "environment": {"python": "3.11", "cuda": None, "libraries": {}},
            "datasets": [{"name": "d.jsonl", "hash": "sha256:def", "source": "d.jsonl",
                          "size_bytes": 10}],
        },
    )
    store.write(
        "eval.json",
        {"scores": {"arithmetic": {"after": 0.9, "before": 0.8, "delta": 0.1,
                                   "regression": False}}},
    )
    store.write("gate.json", {"gate_verdict": "SHIP", "gate_reasons": []})
    store.write(
        "scan.json",
        {"status": "clean", "integrity": "ok",
         "backdoor_scan": {"status": "clean", "findings": []}},
    )
    return store


def test_build_maps_all_blocks(tmp_path):
    store = _seed_run(tmp_path)
    passport = build_passport(store, model_name="m", model_version="1.0.0")
    blocks = passport["blocks"]
    assert blocks["identity"]["base_model"]["name"] == "tiny-llm"
    assert blocks["data_provenance"]["datasets"][0]["name"] == "d.jsonl"
    assert blocks["training_record"]["method"] == "lora"
    assert blocks["evaluation"]["gate_verdict"] == "SHIP"
    assert blocks["security"]["integrity"] == "ok"
    assert passport["provenance_class"] == "native"


def test_missing_evidence_marks_unattested(tmp_path):
    store = RunStore(tmp_path / ".soup")  # empty run dir
    passport = build_passport(store, model_name="m", model_version="1.0.0")
    ua = passport["unattested_fields"]
    assert "blocks.security" in ua
    assert "blocks.evaluation.scores" in ua
    assert "blocks.identity.base_model" in ua


@requires_crypto
def test_build_sign_verify_roundtrip(tmp_path):
    store = _seed_run(tmp_path)
    passport = build_passport(store, model_name="acme", model_version="1.3.0")
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    result = crypto.verify_passport(passport)
    assert result.valid
    assert result.gate_verdict == "SHIP"
    assert result.model_name == "acme"


@requires_crypto
def test_tamper_any_block_breaks_verify(tmp_path):
    store = _seed_run(tmp_path)
    passport = build_passport(store, model_name="acme", model_version="1.3.0")
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    # Change one score value.
    passport["blocks"]["evaluation"]["scores"]["arithmetic"]["after"] = 0.1
    result = crypto.verify_passport(passport)
    assert not result.valid
    assert any("evaluation" in r for r in result.reasons)


@requires_crypto
def test_lineage_parent_diff(tmp_path):
    store = _seed_run(tmp_path)
    parent = build_passport(store, model_name="acme", model_version="1.0.0")
    key = crypto.generate_private_key()
    crypto.sign_passport(parent, key, signer_type="self")

    # Child run with an improved score.
    store.write(
        "eval.json",
        {"scores": {"arithmetic": {"after": 0.95, "before": 0.9, "delta": 0.05,
                                   "regression": False}}},
    )
    child = build_passport(store, model_name="acme", model_version="1.1.0",
                           parent_passport=parent)
    assert child["blocks"]["lineage"]["parent_passport_hash"]
    assert "arithmetic" in child["blocks"]["lineage"]["diff_from_parent"]


def test_render_markdown_and_terminal(tmp_path):
    from rich.console import Console

    from soup_cli.passport.render import render_markdown, render_terminal

    store = _seed_run(tmp_path)
    passport = build_passport(store, model_name="m", model_version="1.0.0")
    md = render_markdown(passport)
    assert "# Model Passport" in md
    assert "audit-ready" in md.lower()
    # terminal render must not raise
    render_terminal(passport, Console(file=open("/dev/null", "w")))
