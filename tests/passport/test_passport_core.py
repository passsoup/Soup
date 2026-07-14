"""Phase 0 — passport core: canonical hashing, hash chain, sign/verify, run store."""

from __future__ import annotations

import json

import pytest

from soup_cli.passport import crypto, hashing, schema
from soup_cli.passport.runstore import RunStore

pytestmark = pytest.mark.unit

_HAS_CRYPTO = crypto.is_available()
requires_crypto = pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")


# --------------------------------------------------------------------------- #
# Canonical hashing
# --------------------------------------------------------------------------- #
def test_canonical_json_is_key_order_independent():
    a = {"b": 1, "a": 2, "nested": {"y": 1, "x": 2}}
    b = {"a": 2, "nested": {"x": 2, "y": 1}, "b": 1}
    assert hashing.canonical_json(a) == hashing.canonical_json(b)
    assert hashing.hash_obj(a) == hashing.hash_obj(b)


def test_canonical_json_no_whitespace():
    assert hashing.canonical_json({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_sha256_hex_prefixed():
    digest = hashing.sha256_hex(b"soup")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


def test_hash_file(tmp_path):
    p = tmp_path / "w.bin"
    p.write_bytes(b"weights" * 1000)
    assert hashing.hash_file(p) == hashing.sha256_hex(b"weights" * 1000)


def test_hash_dir_stable_and_content_sensitive(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "sub" / "b.txt").write_text("world")
    h1 = hashing.hash_dir(tmp_path)
    h2 = hashing.hash_dir(tmp_path)
    assert h1 == h2
    (tmp_path / "sub" / "b.txt").write_text("worle")  # one byte
    assert hashing.hash_dir(tmp_path) != h1


# --------------------------------------------------------------------------- #
# Hash chain + tamper detection
# --------------------------------------------------------------------------- #
def _sample_blocks():
    blocks = schema.empty_blocks()
    blocks["identity"]["base_model"]["name"] = "tiny-llm"
    blocks["evaluation"]["gate_verdict"] = "SHIP"
    return blocks


def test_hash_chain_roundtrips():
    blocks = _sample_blocks()
    passport = schema.assemble_passport(
        model_name="m", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks,
    )
    ok, problems = schema.verify_hash_chain(passport)
    assert ok, problems


def test_hash_chain_detects_single_byte_change():
    blocks = _sample_blocks()
    passport = schema.assemble_passport(
        model_name="m", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks,
    )
    passport["blocks"]["evaluation"]["gate_verdict"] = "DONT_SHIP"  # tamper
    ok, problems = schema.verify_hash_chain(passport)
    assert not ok
    assert any("evaluation" in p for p in problems)


# --------------------------------------------------------------------------- #
# Sign / verify
# --------------------------------------------------------------------------- #
@requires_crypto
def test_sign_and_verify_roundtrip():
    blocks = _sample_blocks()
    passport = schema.assemble_passport(
        model_name="meplay", model_version="1.3.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks,
    )
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    result = crypto.verify_passport(passport)
    assert result.valid
    assert result.provenance_class == "native"
    assert result.model_name == "meplay"
    assert result.gate_verdict == "SHIP"


@requires_crypto
def test_verify_fails_on_tampered_block():
    blocks = _sample_blocks()
    passport = schema.assemble_passport(
        model_name="meplay", model_version="1.3.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks,
    )
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    # Flip one byte in a block without recomputing the chain.
    passport["blocks"]["identity"]["base_model"]["name"] = "evil-llm"
    result = crypto.verify_passport(passport)
    assert not result.valid


@requires_crypto
def test_verify_fails_on_forged_signature():
    blocks = _sample_blocks()
    passport = schema.assemble_passport(
        model_name="meplay", model_version="1.3.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks,
    )
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    passport["signature"]["value"] = "AAAA" + passport["signature"]["value"][4:]
    result = crypto.verify_passport(passport)
    assert not result.valid


@requires_crypto
def test_verify_trusted_key_match():
    blocks = _sample_blocks()
    passport = schema.assemble_passport(
        model_name="meplay", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks,
    )
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="org", signer_label="MePlay Corp")
    good = crypto.public_key_b64(key)
    r = crypto.verify_passport(passport, trusted_public_key_b64=good)
    assert r.valid and r.trusted_key_match and r.signer_label == "MePlay Corp"

    other = crypto.public_key_b64(crypto.generate_private_key())
    r2 = crypto.verify_passport(passport, trusted_public_key_b64=other)
    assert not r2.valid and r2.trusted_key_match is False


# --------------------------------------------------------------------------- #
# Run store
# --------------------------------------------------------------------------- #
def test_runstore_write_read(tmp_path):
    store = RunStore(tmp_path / ".soup")
    store.write("eval.json", {"scores": {"a": 1}})
    assert store.read("eval.json") == {"scores": {"a": 1}}
    assert store.read_optional("missing.json") is None


def test_runstore_rejects_symlink(tmp_path):
    import os

    store = RunStore(tmp_path / ".soup")
    store.root.mkdir(parents=True)
    victim = tmp_path / "victim.json"
    victim.write_text("{}")
    link = store.root / "gate.json"
    os.symlink(victim, link)
    with pytest.raises(ValueError):
        store.write("gate.json", {"x": 1})


def test_passport_serialises_to_json(tmp_path):
    blocks = _sample_blocks()
    passport = schema.assemble_passport(
        model_name="m", model_version="1.0.0", created_at="2026-07-14T00:00:00Z",
        blocks=blocks,
    )
    text = json.dumps(passport)
    assert json.loads(text)["soup_passport_version"] == "1.0"
