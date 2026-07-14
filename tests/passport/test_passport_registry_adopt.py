"""Phase 4 — passport registry (store/server/client) + adopt attested passports."""

from __future__ import annotations

import threading

import pytest

from soup_cli.passport import crypto
from soup_cli.passport.builder import build_passport
from soup_cli.passport.registry import (
    PassportStore,
    RegistryClient,
    make_server,
    passport_id,
)
from soup_cli.passport.runstore import RunStore
from soup_cli.passport.schema import PROVENANCE_ATTESTED

pytestmark = pytest.mark.unit

requires_crypto = pytest.mark.skipif(
    not crypto.is_available(), reason="cryptography not installed"
)


def _signed_passport(tmp_path, name="m", version="1.0.0", provenance="native"):
    store = RunStore(tmp_path / ".soup")
    store.write("scan.json", {"status": "clean", "integrity": "ok",
                              "backdoor_scan": {"status": "clean", "findings": []}})
    passport = build_passport(store, model_name=name, model_version=version,
                              provenance_class=provenance)
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    return passport


# --------------------------------------------------------------------------- #
# store
# --------------------------------------------------------------------------- #
@requires_crypto
def test_store_put_get_content_addressed(tmp_path):
    store = PassportStore(tmp_path / "reg")
    p = _signed_passport(tmp_path)
    pid = store.put(p)
    assert pid == passport_id(p)
    assert store.get(pid) == p
    # Same passport dedupes to the same id.
    assert store.put(p) == pid


@requires_crypto
def test_store_list_and_verify(tmp_path):
    store = PassportStore(tmp_path / "reg")
    pid = store.put(_signed_passport(tmp_path, name="meplay"))
    items = store.list()
    assert len(items) == 1 and items[0]["name"] == "meplay"
    result = store.verify(pid)
    assert result["valid"] is True


def test_store_get_missing_returns_none(tmp_path):
    store = PassportStore(tmp_path / "reg")
    assert store.get("deadbeefdeadbeef") is None


def test_store_rejects_bad_id(tmp_path):
    store = PassportStore(tmp_path / "reg")
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")


# --------------------------------------------------------------------------- #
# server + client roundtrip
# --------------------------------------------------------------------------- #
@requires_crypto
def test_server_client_roundtrip(tmp_path):
    store = PassportStore(tmp_path / "reg")
    server = make_server("127.0.0.1", 0, store, token="tok")
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        client = RegistryClient(f"http://127.0.0.1:{port}", token="tok")
        p = _signed_passport(tmp_path, name="meplay", version="2.0.0")
        pid = client.push(p)
        assert pid == passport_id(p)
        assert client.pull(pid)["model"]["version"] == "2.0.0"
        listing = client.list()
        assert any(i["id"] == pid for i in listing)
    finally:
        server.shutdown()
        server.server_close()


@requires_crypto
def test_server_rejects_unauthorized(tmp_path):
    from soup_cli.passport.registry import RegistryError

    store = PassportStore(tmp_path / "reg")
    server = make_server("127.0.0.1", 0, store, token="secret")
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        bad = RegistryClient(f"http://127.0.0.1:{port}", token="wrong")
        with pytest.raises(RegistryError):
            bad.push(_signed_passport(tmp_path))
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# adopt -> attested passport
# --------------------------------------------------------------------------- #
@requires_crypto
def test_adopt_produces_attested_passport(tmp_path):
    # Simulate what `soup adopt` builds: scan evidence only, attested class.
    store = RunStore(tmp_path / ".soup")
    store.write("scan.json", {"status": "clean", "integrity": "ok",
                              "backdoor_scan": {"status": "clean", "findings": []}})
    passport = build_passport(store, model_name="vendor-llm", model_version="1.0.0",
                              provenance_class=PROVENANCE_ATTESTED)
    key = crypto.generate_private_key()
    crypto.sign_passport(passport, key, signer_type="self")
    result = crypto.verify_passport(passport)
    assert result.valid
    assert result.provenance_class == "attested"
    # External training was not witnessed -> honestly unattested.
    assert "blocks.training_record" in passport["unattested_fields"]
    assert "blocks.identity.base_model" in passport["unattested_fields"]


def test_bank_mrm_pack_registered():
    from soup_cli.passport.packs import get_pack

    pack = get_pack("bank-mrm")
    assert pack.tier == "enterprise"
    assert pack.feature_key() == "pack:bank-mrm"
