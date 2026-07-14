"""Phase 3 — offline licensing, org signing, export packs."""

from __future__ import annotations

import base64
import json

import pytest

from soup_cli.passport import crypto, licensing
from soup_cli.passport.hashing import canonical_bytes

pytestmark = pytest.mark.unit

requires_crypto = pytest.mark.skipif(
    not crypto.is_available(), reason="cryptography not installed"
)


# --------------------------------------------------------------------------- #
# helpers — sign a license with a throwaway key, monkeypatch the anchor
# --------------------------------------------------------------------------- #
def _make_license(monkeypatch, **overrides):
    """Return a signed license doc signed by a fresh key that is patched in as anchor."""
    from cryptography.hazmat.primitives import serialization

    key = crypto.generate_private_key()
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pub_b64 = base64.b64encode(pub_raw).decode()
    monkeypatch.setattr(licensing, "_ISSUER_PUBLIC_KEY_B64", pub_b64)

    lic = {
        "org_id": "acme-corp",
        "tier": "pro",
        "features": ["org-signing", "pack:eu-ai-act-gpai"],
        "adopt_credits": 3,
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2999-01-01T00:00:00+00:00",
    }
    lic.update(overrides)
    sig = key.sign(canonical_bytes(lic))
    return {
        "license": lic,
        "signature": {
            "algorithm": "ed25519",
            "value": base64.b64encode(sig).decode(),
            "public_key": pub_b64,
        },
    }


@requires_crypto
def test_valid_license_activates(tmp_path, monkeypatch):
    monkeypatch.setattr(licensing.Path, "home", classmethod(lambda cls: tmp_path))
    doc = _make_license(monkeypatch)
    f = tmp_path / "acme.license.key"
    f.write_text(json.dumps(doc))
    lic = licensing.activate(str(f))
    assert lic.org_id == "acme-corp"
    assert lic.covers("org-signing")
    assert lic.covers("pack:eu-ai-act-gpai")
    # pro tier implies pack:gdpr even though not listed
    assert lic.covers("pack:gdpr")
    # but NOT an enterprise-only pack
    assert not lic.covers("pack:bank-mrm")


@requires_crypto
def test_tampered_license_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(licensing.Path, "home", classmethod(lambda cls: tmp_path))
    doc = _make_license(monkeypatch)
    doc["license"]["tier"] = "enterprise"  # tamper after signing
    f = tmp_path / "bad.license.key"
    f.write_text(json.dumps(doc))
    with pytest.raises(licensing.LicenseError):
        licensing.activate(str(f))


@requires_crypto
def test_expired_license_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(licensing.Path, "home", classmethod(lambda cls: tmp_path))
    doc = _make_license(monkeypatch, expires_at="2000-01-01T00:00:00+00:00")
    f = tmp_path / "old.license.key"
    f.write_text(json.dumps(doc))
    with pytest.raises(licensing.LicenseError):
        licensing.activate(str(f))


@requires_crypto
def test_require_gates_without_license(tmp_path, monkeypatch):
    monkeypatch.setattr(licensing.Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(licensing.LicenseError):
        licensing.require("org-signing")


@requires_crypto
def test_require_passes_with_license(tmp_path, monkeypatch):
    monkeypatch.setattr(licensing.Path, "home", classmethod(lambda cls: tmp_path))
    doc = _make_license(monkeypatch)
    f = tmp_path / "acme.license.key"
    f.write_text(json.dumps(doc))
    licensing.activate(str(f))
    lic = licensing.require("org-signing")
    assert lic.tier == "pro"
    with pytest.raises(licensing.LicenseError):
        licensing.require("airgap")  # not covered by pro


@requires_crypto
def test_adopt_credits_decrement(tmp_path, monkeypatch):
    monkeypatch.setattr(licensing.Path, "home", classmethod(lambda cls: tmp_path))
    doc = _make_license(monkeypatch, adopt_credits=2)
    f = tmp_path / "acme.license.key"
    f.write_text(json.dumps(doc))
    licensing.activate(str(f))
    assert licensing.remaining_adopt_credits() == 2
    assert licensing.decrement_adopt_credit() == 1
    assert licensing.decrement_adopt_credit() == 0
    with pytest.raises(licensing.LicenseError):
        licensing.decrement_adopt_credit()
    # the signed license file itself was never mutated -> still valid
    assert licensing.load_active_license() is not None


# --------------------------------------------------------------------------- #
# signers + org signing
# --------------------------------------------------------------------------- #
@requires_crypto
def test_file_signer_roundtrip():
    from soup_cli.passport.schema import assemble_passport, empty_blocks
    from soup_cli.passport.signers import FileSigner

    signer = FileSigner.generate()
    passport = assemble_passport(
        model_name="m", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=empty_blocks(),
    )
    crypto.sign_passport_with_signer(passport, signer, signer_type="org", signer_label="Acme")
    result = crypto.verify_passport(passport)
    assert result.valid
    assert result.signer_type == "org"
    assert result.signer_label == "Acme"


def test_pkcs11_signer_is_stub():
    from soup_cli.passport.signers import Pkcs11Signer

    with pytest.raises(NotImplementedError):
        Pkcs11Signer().public_key_b64()


# --------------------------------------------------------------------------- #
# packs
# --------------------------------------------------------------------------- #
def _sample_passport():
    from soup_cli.passport.schema import assemble_passport, empty_blocks

    blocks = empty_blocks()
    blocks["identity"]["base_model"]["name"] = "tiny-llm"
    blocks["evaluation"]["scores"] = {"arithmetic": {"after": 0.9, "before": 0.8,
                                                      "delta": 0.1, "regression": False}}
    blocks["evaluation"]["gate_verdict"] = "SHIP"
    blocks["security"]["integrity"] = "ok"
    return assemble_passport(
        model_name="acme", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks, unattested_fields=["blocks.data_provenance.pii_scan"],
    )


def test_model_card_pack_renders():
    from soup_cli.passport.packs import render_pack

    md = render_pack("model-card", _sample_passport())
    assert "Model Card" in md
    assert "tiny-llm" in md
    assert "audit-ready" in md.lower()
    assert "compliant" not in md.lower()  # forbidden word (Rule §3)


def test_gpai_pack_renders():
    from soup_cli.passport.packs import render_pack

    md = render_pack("eu-ai-act-gpai", _sample_passport())
    assert "GPAI" in md
    assert "public summary of training content" in md.lower()
    assert "compliant" not in md.lower()


def test_pack_tiers():
    from soup_cli.passport.packs import get_pack

    assert get_pack("model-card").tier == "free"
    assert get_pack("model-card").feature_key() is None
    assert get_pack("eu-ai-act-gpai").feature_key() == "pack:eu-ai-act-gpai"
