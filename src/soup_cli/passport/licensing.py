"""Offline license activation + feature gating (spec §3, JetBrains-style).

The open-core boundary: individual capability is free forever; *organisational
proof* is paid. A paid command calls :func:`require` at its very first line; with
no valid license it prints a clear message and exits 3.

Everything is offline by construction — that is a hard requirement of "air-gap by
birth". A license is a **signed JSON file** the seller issues; the CLI verifies it
with the issuer's **public key, baked into this module** (``_ISSUER_PUBLIC_KEY_B64``,
the same key as ``keys/license_pub.pem`` in the repo). The issuer's *private* key
never ships. No server, no phone-home, ever.

BYOM accounting (``adopt_credits``) is decremented locally and honestly — in an
air-gap world it is a trust-based flat model, exactly as the spec intends.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from soup_cli.passport import crypto
from soup_cli.passport.environ import utc_now_iso
from soup_cli.passport.hashing import canonical_bytes

# The license issuer's PUBLIC key (raw ed25519, base64). This is the trust anchor
# baked into the product — identical to keys/license_pub.pem. Verifying against a
# constant (not a file that could be swapped) is the whole point of "вшитый ключ".
_ISSUER_PUBLIC_KEY_B64 = "HOA9rBBlFhm2DC65Pn50MqxADU04p8b4D212Jl15AeM="

TIER_PRO = "pro"
TIER_ENTERPRISE = "enterprise"
_TIERS = (TIER_PRO, TIER_ENTERPRISE)

# Tier -> features a tier implicitly grants even if not listed explicitly.
# Enterprise is a superset of Pro.
_TIER_FEATURES = {
    TIER_PRO: {
        "org-signing",
        "registry",
        "pack:eu-ai-act-gpai",
        "pack:gdpr",
        "adopt",
    },
    TIER_ENTERPRISE: {
        "org-signing",
        "registry",
        "adopt",
        "airgap",
        "pack:eu-ai-act-gpai",
        "pack:gdpr",
        "pack:bank-mrm",
        "pack:eu-ai-act-highrisk",
        "pack:hipaa",
        "pack:nist-ai-rmf",
        "pack:iso-42001",
    },
}


class LicenseError(Exception):
    """Raised when a paid feature is used without a valid covering license (exit 3)."""


@dataclass
class License:
    org_id: str
    tier: str
    features: list[str]
    issued_at: Optional[str]
    expires_at: Optional[str]
    adopt_credits: Optional[int] = None
    raw: Optional[dict] = None

    def covers(self, feature: str) -> bool:
        if feature in self.features:
            return True
        return feature in _TIER_FEATURES.get(self.tier, set())

    def is_expired(self, *, now_iso: Optional[str] = None) -> bool:
        if not self.expires_at:
            return False
        now = now_iso or utc_now_iso()
        # ISO-8601 strings compare lexicographically when both are UTC 'Z'/offset.
        return str(now) > str(self.expires_at)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "tier": self.tier,
            "features": sorted(self.effective_features()),
            "adopt_credits": self.adopt_credits,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def effective_features(self) -> set[str]:
        return set(self.features) | _TIER_FEATURES.get(self.tier, set())


def license_store_path() -> Path:
    return Path.home() / ".soup" / "license.key"


def _verify_license_signature(doc: dict) -> bool:
    """Verify the license signature over its canonical ``license`` object.

    Trust anchor is the baked-in issuer public key — the ``public_key`` field in
    the file is only informational and is cross-checked against the anchor.
    """
    lic = doc.get("license")
    sig = doc.get("signature")
    if not isinstance(lic, dict) or not isinstance(sig, dict):
        return False
    if not crypto.is_available():
        raise LicenseError(
            "license verification needs the 'cryptography' package: "
            "pip install 'soup-cli[sign]'"
        )
    import base64

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    # Cross-check: if the file embeds a public key, it must equal the anchor.
    embedded = sig.get("public_key")
    if embedded and crypto._b64_eq(embedded, _ISSUER_PUBLIC_KEY_B64) is False:
        return False

    try:
        sig_bytes = base64.b64decode(sig.get("value", ""), validate=True)
        pub_raw = base64.b64decode(_ISSUER_PUBLIC_KEY_B64, validate=True)
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        pub.verify(sig_bytes, canonical_bytes(lic))
    except (InvalidSignature, ValueError):
        return False
    return True


def parse_license(doc: dict) -> License:
    """Parse (without verifying) a license document into a :class:`License`."""
    lic = doc.get("license", {})
    tier = str(lic.get("tier", "")).lower()
    return License(
        org_id=str(lic.get("org_id", "")),
        tier=tier,
        features=list(lic.get("features", [])),
        issued_at=lic.get("issued_at"),
        expires_at=lic.get("expires_at"),
        adopt_credits=lic.get("adopt_credits"),
        raw=doc,
    )


def validate_license(doc: dict) -> License:
    """Verify signature + tier + expiry; return the :class:`License` or raise."""
    if not _verify_license_signature(doc):
        raise LicenseError("license signature is invalid (not issued by Soup or tampered).")
    lic = parse_license(doc)
    if lic.tier not in _TIERS:
        raise LicenseError(f"license tier {lic.tier!r} is not recognised.")
    if lic.is_expired():
        raise LicenseError(f"license expired on {lic.expires_at}.")
    return lic


def activate(license_path: str) -> License:
    """Verify a license file and persist it to ``~/.soup/license.key``."""
    p = Path(license_path)
    if not p.is_file():
        raise LicenseError(f"license file not found: {license_path}")
    if p.stat().st_size > 256 * 1024:
        raise LicenseError("license file is implausibly large.")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LicenseError(f"could not read license: {exc}") from exc
    lic = validate_license(doc)

    dest = license_store_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    return lic


def deactivate() -> bool:
    """Remove the active license. Returns True if one was present."""
    dest = license_store_path()
    if dest.exists():
        dest.unlink()
        return True
    return False


def load_active_license() -> Optional[License]:
    """Return the active, valid license, or ``None`` if absent/invalid/expired."""
    dest = license_store_path()
    if not dest.is_file():
        return None
    try:
        doc = json.loads(dest.read_text(encoding="utf-8"))
        return validate_license(doc)
    except (OSError, json.JSONDecodeError, LicenseError):
        return None


def require(feature: str) -> License:
    """Gate a paid feature. Return the license, or raise :class:`LicenseError`.

    The message is the exact operator guidance from the spec.
    """
    lic = load_active_license()
    if lic is None:
        raise LicenseError(
            f"Requires a Pro/Enterprise license for '{feature}'. "
            f"Activate it with:  soup license activate <file>"
        )
    if not lic.covers(feature):
        raise LicenseError(
            f"Your {lic.tier} license does not include '{feature}'. "
            f"Contact sales to extend it, then:  soup license activate <file>"
        )
    return lic


def _state_path() -> Path:
    return Path.home() / ".soup" / "license_state.json"


def _load_state() -> dict:
    p = _state_path()
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def remaining_adopt_credits(lic: Optional[License] = None) -> Optional[int]:
    """Remaining BYOM credits: license grant minus locally-consumed. None = unlimited."""
    lic = lic or load_active_license()
    if lic is None or lic.adopt_credits is None:
        return None  # unlimited (Enterprise) or no license
    consumed = int(_load_state().get(lic.org_id, {}).get("adopt_consumed", 0))
    return max(0, int(lic.adopt_credits) - consumed)


def decrement_adopt_credit() -> Optional[int]:
    """Consume one BYOM credit in the *separate* state file; return remaining.

    The signed license (``license.key``) is never mutated — that would break its
    signature. Consumption is tracked in ``~/.soup/license_state.json`` keyed by
    org_id. Trust-based accounting for air-gap (spec §3.2). Returns ``None`` for
    an unlimited license; raises :class:`LicenseError` at zero.
    """
    lic = load_active_license()
    if lic is None:
        raise LicenseError("no active license.")
    if lic.adopt_credits is None:
        return None  # unlimited
    remaining = remaining_adopt_credits(lic)
    if remaining is not None and remaining <= 0:
        raise LicenseError("adopt credits exhausted; contact sales to extend your license.")

    state = _load_state()
    org_state = state.setdefault(lic.org_id, {})
    org_state["adopt_consumed"] = int(org_state.get("adopt_consumed", 0)) + 1
    org_state["last_adopt_at"] = utc_now_iso()
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    return remaining_adopt_credits(lic)
