"""Passport signing & verification — Ed25519 over the hash-chain root (spec §2).

Design choices, and why:

- **We sign the ``root_hash`` string**, not the whole file. The hash chain
  already binds every block into ``root_hash``; signing that one value keeps the
  signature tiny and makes the "which block changed" diagnostic independent of
  the signature check. This is the detached-signature + public-key-in-envelope
  shape the OMS/Sigstore direction favours (spec §1.4) — not a bespoke format.

- **Raw 32-byte keys / 64-byte signatures, base64-encoded** in the envelope
  (``signature.value`` / ``signature.public_key``). PEM is awkward in a browser;
  raw ed25519 is exactly what the tiny JS verifier on ``/verify`` consumes, so
  the CLI and the web page verify byte-identical inputs (spec file 04).

- **Private keys never leave the machine and are never logged.** Self-sign keys
  live in ``~/.soup/keys`` (private ``0600``). Org keys come from a pluggable
  :class:`~soup_cli.passport.signers.Signer` backend (file / HSM / PKCS#11).

``cryptography`` is imported lazily (it lives in the ``[sign]`` extra) so the
light CLI stays torch-free and import-cheap.
"""

from __future__ import annotations

import base64
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from soup_cli.passport.schema import (
    PROVENANCE_CLASSES,
    validate_structure,
    verify_hash_chain,
)

ALGORITHM = "ed25519"


def is_available() -> bool:
    """True when the ``cryptography`` ed25519 backend is importable."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: F401
            Ed25519PrivateKey,
        )
    except Exception:  # noqa: BLE001 — a broken/partial backend must read as "unavailable"
        return False
    return True


def _require() -> None:
    if not is_available():
        raise RuntimeError(
            "Passport signing needs the 'cryptography' package. "
            "Install with:  pip install 'soup-cli[sign]'"
        )


# --------------------------------------------------------------------------- #
# Key material
# --------------------------------------------------------------------------- #
def generate_private_key() -> Any:
    """Return a fresh ed25519 private key object."""
    _require()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate()


def _private_pem(private_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(private_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_b64(private_key: Any) -> str:
    """Base64 of the raw 32-byte ed25519 public key (envelope form)."""
    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def load_private_key_pem(path: str | Path) -> Any:
    """Load an ed25519 private key from a PEM file (symlink-rejected, size-capped)."""
    _require()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    p = os.fspath(path)
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"key {os.path.basename(p)!r} must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"key {os.path.basename(p)!r} must be a regular file")
    if st.st_size > 64 * 1024:
        raise ValueError("key file exceeds 64 KiB")
    with open(p, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("key must be ed25519")
    return key


def load_or_create_self_key(keys_dir: Optional[str | Path] = None) -> Any:
    """Return the user's self-sign private key, creating one on first use.

    Stored at ``~/.soup/keys/id_ed25519`` (private, ``0600``) with the public
    half beside it. The private key is never printed or logged.
    """
    _require()
    base = Path(keys_dir) if keys_dir else Path.home() / ".soup" / "keys"
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    priv_path = base / "id_ed25519"
    if priv_path.exists():
        return load_private_key_pem(priv_path)

    key = generate_private_key()
    # Write private key 0600 via a restrictive-mode temp file, then rename.
    fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(_private_pem(key))
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    with open(str(priv_path) + ".pub", "wb") as fh:
        fh.write(_public_pem(key))
    return key


# --------------------------------------------------------------------------- #
# Low-level sign / verify over the root hash string
# --------------------------------------------------------------------------- #
def sign_root_hash(private_key: Any, root_hash: str) -> dict[str, str]:
    """Sign the ``root_hash`` string; return the passport ``signature`` envelope."""
    _require()
    sig = private_key.sign(root_hash.encode("utf-8"))
    return {
        "algorithm": ALGORITHM,
        "value": base64.b64encode(sig).decode("ascii"),
        "public_key": public_key_b64(private_key),
    }


def verify_root_hash_signature(root_hash: str, signature: dict[str, Any]) -> bool:
    """Verify a signature envelope over ``root_hash``. False on any failure."""
    _require()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != ALGORITHM:
        return False
    try:
        sig = base64.b64decode(signature.get("value", ""), validate=True)
        pub_raw = base64.b64decode(signature.get("public_key", ""), validate=True)
    except (ValueError, TypeError):
        return False
    if len(pub_raw) != 32:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        pub.verify(sig, root_hash.encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False
    return True


# --------------------------------------------------------------------------- #
# Passport-level sign / verify
# --------------------------------------------------------------------------- #
def sign_passport(
    passport: dict[str, Any],
    private_key: Any,
    *,
    signer_type: str = "self",
    signer_label: Optional[str] = None,
) -> dict[str, Any]:
    """Attach a ``signature`` and fill the accountability signer block.

    ``signer_type`` is ``"self"`` (personal key) or ``"org"`` (organisation
    identity). ``signer_label`` is the display name a verifier shows
    ("Acme Corp") — a *claim*, never a trust assertion (spec §2).

    The signer identity is written into the accountability block *before* the
    hash chain is (re)computed, so the signer is itself tamper-evident: you
    cannot swap the claimed signer without breaking the signature.
    """
    from soup_cli.passport.schema import build_hash_chain

    signer = passport.setdefault("blocks", {}).setdefault("accountability", {}).setdefault(
        "signer", {}
    )
    signer["type"] = signer_type
    signer["label"] = signer_label
    signer["public_key"] = public_key_b64(private_key)

    # Recompute the chain so the just-written signer block is covered by root_hash.
    passport["hash_chain"] = build_hash_chain(passport["blocks"])
    root_hash = passport["hash_chain"]["root_hash"]
    passport["signature"] = sign_root_hash(private_key, root_hash)
    return passport


@dataclass
class VerifyResult:
    """Outcome of verifying a passport — the shared shape CLI and web both use."""

    valid: bool
    reasons: list[str] = field(default_factory=list)
    provenance_class: Optional[str] = None
    signer_type: Optional[str] = None
    signer_label: Optional[str] = None
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    gate_verdict: Optional[str] = None
    unattested_fields: list[str] = field(default_factory=list)
    trusted_key_match: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reasons": self.reasons,
            "provenance_class": self.provenance_class,
            "signer_type": self.signer_type,
            "signer_label": self.signer_label,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "gate_verdict": self.gate_verdict,
            "unattested_fields": self.unattested_fields,
            "trusted_key_match": self.trusted_key_match,
        }


def verify_passport(
    passport: Any, *, trusted_public_key_b64: Optional[str] = None
) -> VerifyResult:
    """Verify a passport end to end: structure, hash chain, signature.

    This is the *single* verification algorithm. ``soup verify`` calls it, the
    registry calls it, and the ``/verify`` browser code reimplements exactly
    these steps. If ``trusted_public_key_b64`` is supplied, the result also
    reports whether the embedded key matches it — but a mismatch does not by
    itself make the passport invalid (we are not a CA; the passport is
    mathematically valid regardless of whether *you* trust the key).
    """
    result = VerifyResult(valid=False)

    structural = validate_structure(passport)
    if structural:
        result.reasons = structural
        return result

    result.provenance_class = passport.get("provenance_class")
    model = passport.get("model", {})
    result.model_name = model.get("name")
    result.model_version = model.get("version")
    result.gate_verdict = (
        passport.get("blocks", {}).get("evaluation", {}).get("gate_verdict")
    )
    unattested = passport.get("unattested_fields", [])
    result.unattested_fields = list(unattested) if isinstance(unattested, list) else []

    signer = passport.get("blocks", {}).get("accountability", {}).get("signer", {})
    if isinstance(signer, dict):
        result.signer_type = signer.get("type")
        result.signer_label = signer.get("label")

    if result.provenance_class not in PROVENANCE_CLASSES:
        result.reasons.append(f"unknown provenance_class {result.provenance_class!r}")

    chain_ok, chain_problems = verify_hash_chain(passport)
    if not chain_ok:
        result.reasons.extend(chain_problems)

    signature = passport.get("signature")
    if not isinstance(signature, dict) or not signature.get("value"):
        result.reasons.append("passport is not signed")
        return result

    if not is_available():
        result.reasons.append(
            "cannot check signature: install 'soup-cli[sign]' (cryptography)"
        )
        return result

    root_hash = passport.get("hash_chain", {}).get("root_hash", "")
    sig_ok = verify_root_hash_signature(root_hash, signature)
    if not sig_ok:
        result.reasons.append("signature is invalid (tampered or wrong key)")

    if trusted_public_key_b64 is not None:
        embedded = signature.get("public_key", "")
        result.trusted_key_match = _b64_eq(embedded, trusted_public_key_b64)
        if not result.trusted_key_match:
            result.reasons.append("signed by an untrusted key (does not match --key)")

    result.valid = chain_ok and sig_ok and not structural
    if result.valid and trusted_public_key_b64 is not None:
        result.valid = bool(result.trusted_key_match)
    return result


def _b64_eq(a: str, b: str) -> bool:
    """Compare two base64 strings by their decoded bytes (whitespace-insensitive)."""
    try:
        return base64.b64decode(a, validate=True) == base64.b64decode(b, validate=True)
    except (ValueError, TypeError):
        return "".join(str(a).split()) == "".join(str(b).split())
