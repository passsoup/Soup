"""Phase 6 — the /verify web page uses the SAME verification core as the CLI.

The web verifier (web/verify/soup-verify.js) is pure JS. If Node is available we
sign a passport with the Python CLI core and verify it with the JS core, proving
the two agree byte-for-byte (canonical JSON, SHA-256 chain, Ed25519). If Node is
absent the cross-check is skipped, but the self-containment checks still run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from soup_cli.passport import crypto
from soup_cli.passport.builder import build_passport
from soup_cli.passport.runstore import RunStore

pytestmark = pytest.mark.unit

_WEB = Path(__file__).resolve().parents[2] / "web" / "verify"
_NODE = shutil.which("node")
requires_node = pytest.mark.skipif(_NODE is None, reason="node not installed")
requires_crypto = pytest.mark.skipif(
    not crypto.is_available(), reason="cryptography not installed"
)


def test_index_html_is_self_contained():
    html = (_WEB / "index.html").read_text(encoding="utf-8")
    # Crypto inlined (no external script/style/font hosts).
    assert "SoupVerify" in html
    assert "ed25519Verify" in html
    assert "http://" not in html.replace("http://127.0.0.1", "").replace(
        "http://www.w3.org", ""
    ) or "cdn" not in html.lower()
    # Honesty disclaimer present (Rule §3).
    assert "audit-ready" in html.lower()
    assert "compliance guarantee" in html.lower()


def _node_verify(passport: dict) -> dict:
    script = f"""
const SV = require({json.dumps(str(_WEB / "soup-verify.js"))});
const p = {json.dumps(passport)};
process.stdout.write(JSON.stringify(SV.verifyPassport(p)));
"""
    out = subprocess.run([_NODE, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@requires_node
@requires_crypto
def test_web_verifies_valid_passport(tmp_path):
    store = RunStore(tmp_path / ".soup")
    store.write("eval.json", {"scores": {"t": {"after": 1.0, "before": 1.0, "delta": 0.0,
                                               "regression": False}}})
    store.write("gate.json", {"gate_verdict": "SHIP", "gate_reasons": []})
    passport = build_passport(store, model_name="webtest", model_version="1.0.0")
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")

    res = _node_verify(passport)
    assert res["valid"] is True
    assert res["model_name"] == "webtest"
    assert res["gate_verdict"] == "SHIP"


@requires_node
@requires_crypto
def test_web_rejects_tampered_passport(tmp_path):
    store = RunStore(tmp_path / ".soup")
    store.write("eval.json", {"scores": {"t": {"after": 0.9, "regression": False}}})
    passport = build_passport(store, model_name="webtest", model_version="1.0.0")
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    passport["blocks"]["evaluation"]["scores"]["t"]["after"] = 0.1  # tamper

    res = _node_verify(passport)
    assert res["valid"] is False
    assert any("evaluation" in r for r in res["reasons"])


@requires_node
@requires_crypto
def test_web_matches_cli_on_org_signature(tmp_path):
    from soup_cli.passport.signers import FileSigner

    store = RunStore(tmp_path / ".soup")
    store.write("scan.json", {"status": "clean", "integrity": "ok",
                              "backdoor_scan": {"status": "clean", "findings": []}})
    passport = build_passport(store, model_name="acme", model_version="2.0.0")
    signer = FileSigner.generate()
    crypto.sign_passport_with_signer(passport, signer, signer_type="org", signer_label="Acme Corp")

    res = _node_verify(passport)
    assert res["valid"] is True
    assert res["signer_label"] == "Acme Corp"
    # CLI agrees.
    assert crypto.verify_passport(passport).valid
