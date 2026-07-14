"""Phase 5 — airgap bundle builder + the remaining regulator packs."""

from __future__ import annotations

import tarfile

import pytest

from soup_cli.passport.airgap import build_bundle
from soup_cli.passport.packs import all_packs, get_pack, render_pack
from soup_cli.passport.schema import assemble_passport, empty_blocks

pytestmark = pytest.mark.unit


def _passport():
    blocks = empty_blocks()
    blocks["identity"]["base_model"]["name"] = "tiny-llm"
    blocks["data_provenance"]["datasets"] = [
        {"name": "d.jsonl", "hash": "sha256:abc", "source": "d.jsonl", "size_bytes": 10}
    ]
    blocks["evaluation"]["scores"] = {"t": {"after": 0.9, "before": 0.8, "delta": 0.1,
                                            "regression": False}}
    blocks["evaluation"]["gate_verdict"] = "SHIP"
    blocks["security"]["integrity"] = "ok"
    return assemble_passport(
        model_name="meplay", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks, unattested_fields=["blocks.data_provenance.pii_scan"],
    )


# --------------------------------------------------------------------------- #
# packs
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name",
    ["model-card", "eu-ai-act-gpai", "gdpr", "bank-mrm", "eu-ai-act-highrisk",
     "hipaa", "nist-ai-rmf", "iso-42001"],
)
def test_all_packs_render_and_are_audit_ready(name):
    md = render_pack(name, _passport())
    assert md and len(md) > 100
    # Rule §3: no forbidden 'compliant' wording; must say audit-ready.
    assert "compliant" not in md.lower()
    assert "audit-ready" in md.lower()
    assert "meplay" in md.lower()


def test_pack_tiers_match_spec():
    tiers = {p.name: p.tier for p in all_packs()}
    assert tiers["model-card"] == "free"
    assert tiers["eu-ai-act-gpai"] == "pro"
    assert tiers["gdpr"] == "pro"
    assert tiers["bank-mrm"] == "enterprise"
    assert tiers["hipaa"] == "enterprise"
    assert get_pack("model-card").feature_key() is None
    assert get_pack("gdpr").feature_key() == "pack:gdpr"


def test_packs_mark_unattested_honestly():
    blocks = empty_blocks()  # almost no evidence
    passport = assemble_passport(
        model_name="bare", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks, unattested_fields=["blocks.security", "blocks.evaluation.scores"],
    )
    md = render_pack("model-card", passport)
    assert "not attested" in md.lower()


# --------------------------------------------------------------------------- #
# airgap bundle
# --------------------------------------------------------------------------- #
def test_build_bundle_contains_pipeline(tmp_path):
    out = tmp_path / "bundle.tar.gz"
    manifest = build_bundle(str(out), include_wheels=False)
    assert out.is_file()
    assert manifest["bundle_sha256"].startswith("sha256:")
    with tarfile.open(out, "r:gz") as tar:
        names = tar.getnames()
    assert "run_pipeline.sh" in names
    assert "manifest.json" in names
    assert any(n.startswith("demo") for n in names)


def test_build_bundle_includes_license(tmp_path):
    lic = tmp_path / "x.license.key"
    lic.write_text("{}")
    out = tmp_path / "bundle.tar.gz"
    manifest = build_bundle(str(out), license_file=str(lic))
    assert "license.key" in manifest["contents"]
