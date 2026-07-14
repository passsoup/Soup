#!/usr/bin/env python3
"""issue_license.py — the seller's license-minting tool (NOT part of the CLI).

This is how you sell Soup: mint a signed, offline license file for a customer.
It signs a ``license`` object with the issuer's **private** key (which lives
outside the repo — never commit it). The customer runs ``soup license activate
<file>`` and the CLI verifies it with the baked-in public key. No server involved.

Usage:

    python tools/issue_license.py \
        --org acme-corp --tier pro \
        --features org-signing pack:eu-ai-act-gpai registry adopt \
        --adopt-credits 10 \
        --expires 2027-07-14 \
        --key tools/secrets/license_issuer_priv.pem \
        --out acme.license.key

Tiers: pro | enterprise. Enterprise implies unlimited adopt credits unless you
pass --adopt-credits. See src/soup_cli/passport/licensing.py for the tier→feature
map (a tier grants its bundle even if you don't list every feature).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone


def _canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _iso(date_str: str) -> str:
    """Accept YYYY-MM-DD or full ISO; return a UTC ISO-8601 string."""
    if "T" in date_str:
        return date_str
    dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return dt.isoformat()


def main() -> int:
    ap = argparse.ArgumentParser(description="Mint a signed offline Soup license.")
    ap.add_argument("--org", required=True, help="Customer org id, e.g. acme-corp.")
    ap.add_argument("--tier", required=True, choices=["pro", "enterprise"])
    ap.add_argument("--features", nargs="*", default=[], help="Explicit feature grants.")
    ap.add_argument(
        "--adopt-credits", type=int, default=None, help="BYOM credits (omit = unlimited)."
    )
    ap.add_argument("--issued", default=None, help="Issue date (default: now).")
    ap.add_argument("--expires", required=True, help="Expiry date YYYY-MM-DD or ISO.")
    ap.add_argument("--key", required=True, help="Issuer private-key PEM path (keep secret!).")
    ap.add_argument("--out", required=True, help="Output license file path.")
    args = ap.parse_args()

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("This tool needs 'cryptography': pip install cryptography", file=sys.stderr)
        return 2

    with open(args.key, "rb") as fh:
        priv = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        print("issuer key must be ed25519", file=sys.stderr)
        return 2

    issued = _iso(args.issued) if args.issued else datetime.now(tz=timezone.utc).isoformat()
    license_obj = {
        "org_id": args.org,
        "tier": args.tier,
        "features": sorted(set(args.features)),
        "adopt_credits": args.adopt_credits,
        "issued_at": issued,
        "expires_at": _iso(args.expires),
    }

    sig = priv.sign(_canonical_bytes(license_obj))
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    doc = {
        "license": license_obj,
        "signature": {
            "algorithm": "ed25519",
            "value": base64.b64encode(sig).decode("ascii"),
            "public_key": base64.b64encode(pub_raw).decode("ascii"),
        },
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    print(f"Wrote license -> {args.out}")
    print(f"  org={args.org} tier={args.tier} expires={license_obj['expires_at']}")
    print(f"  features={license_obj['features']} adopt_credits={args.adopt_credits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
