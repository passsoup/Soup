"""hipaa pack (Enterprise) — de-identification evidence package.

Assembles the passport's data-provenance and PII-scan evidence into a
de-identification evidence package for HIPAA contexts. Audit-ready support for a
covered entity's determination — not a Safe-Harbor or Expert-Determination
certification.
"""

from __future__ import annotations

from soup_cli.passport.packs.base import (
    AUDIT_READY_FOOTER,
    NOT_ATTESTED,
    Pack,
    field,
    header,
    register,
)


def render(passport: dict) -> str:
    lines = header(passport, "HIPAA — De-identification Evidence Package (audit-ready)")
    a = lines.append

    a("> Assembles the technical evidence a covered entity references when "
      "documenting de-identification. It does not itself constitute Safe Harbor "
      "or Expert Determination.")
    a("")

    a("## 1. Model & responsible party")
    model = passport.get("model", {})
    a(f"- **Model:** {model.get('name')} v{model.get('version')}")
    a(f"- **Run by:** {field(passport, 'blocks.accountability.run_by') or NOT_ATTESTED}")
    a(f"- **Signed by:** "
      f"{field(passport, 'blocks.accountability.signer.label') or 'self-signed'}")
    a("")

    a("## 2. Training-data provenance")
    datasets = field(passport, "blocks.data_provenance.datasets", []) or []
    if datasets:
        a("| Dataset | Source | Hash | Size (bytes) |")
        a("|---|---|---|---|")
        for ds in datasets:
            a(f"| {ds.get('name')} | {ds.get('source')} | "
              f"`{ds.get('hash')}` | {ds.get('size_bytes')} |")
    else:
        a(f"- {NOT_ATTESTED}")
    a("")

    a("## 3. PHI / PII screening")
    pii = field(passport, "blocks.data_provenance.pii_scan", {}) or {}
    a(f"- **Screening status:** {pii.get('status', 'unattested')}")
    if pii.get("details"):
        a(f"- **Details:** {pii.get('details')}")
    a("- **Method:** the passport records the screening outcome; the underlying "
      "data never leaves the covered entity's environment (only hashes are stored).")
    a("")

    a("## 4. Integrity controls")
    a(f"- **Artifact integrity:** {field(passport, 'blocks.security.integrity', 'unattested')}")
    a(f"- **Backdoor / tampering scan:** "
      f"{field(passport, 'blocks.security.backdoor_scan.status', 'unattested')}")
    a(f"- **Passport root hash:** `{field(passport, 'hash_chain.root_hash')}`")
    a("")

    a("## 5. Honest gaps (unattested)")
    unattested = passport.get("unattested_fields", [])
    if unattested:
        for u in unattested:
            a(f"- `{u}`")
    else:
        a("- None — all sections are backed by recorded evidence.")

    lines.append(AUDIT_READY_FOOTER)
    return "\n".join(lines)


register(
    Pack(
        name="hipaa",
        tier="enterprise",
        title="HIPAA — de-identification evidence",
        description="De-identification evidence package from data-provenance + PII-scan.",
        render=render,
    )
)
