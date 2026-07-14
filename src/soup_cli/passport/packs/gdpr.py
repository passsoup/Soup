"""gdpr pack (Pro) — DPIA skeleton + Art. 30 processing record.

Assembles the passport's data-provenance evidence (block 2) into a Data
Protection Impact Assessment skeleton and a record of processing activities
(GDPR Art. 30). Audit-ready starting point for a DPO — not a completed DPIA.
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
    lines = header(passport, "GDPR — DPIA Skeleton & Art. 30 Processing Record (audit-ready)")
    a = lines.append

    a("> Draft assembled from the passport's data-provenance evidence. A DPIA "
      "requires legal and contextual judgement this document does not supply; it "
      "organises the technical facts a DPO needs.")
    a("")

    a("## 1. Record of processing activities (Art. 30)")
    a("- **Controller / operator:** "
      f"{field(passport, 'blocks.accountability.run_by') or NOT_ATTESTED}")
    a("- **Purpose of processing:** model fine-tuning / post-training")
    a(f"- **Model:** {passport.get('model', {}).get('name')} "
      f"v{passport.get('model', {}).get('version')}")
    a("")

    a("## 2. Categories of data (from training-data fingerprints)")
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

    a("## 3. Personal-data screening")
    pii = field(passport, "blocks.data_provenance.pii_scan", {}) or {}
    a(f"- **PII scan status:** {pii.get('status', 'unattested')}")
    if pii.get("details"):
        a(f"- **Details:** {pii.get('details')}")
    a(f"- **Lawful basis / origin legality:** "
      f"{field(passport, 'blocks.data_provenance.origin_legality') or NOT_ATTESTED}")
    a("")

    a("## 4. Risk assessment (DPIA skeleton)")
    a("- **Necessity & proportionality:** _to be completed by the DPO._")
    a("- **Risks to data subjects:** _to be completed by the DPO._")
    a("- **Mitigations:** dataset fingerprints above provide immutable provenance; "
      "the signed passport lets a supervisory authority verify what data was used "
      "without accessing the data itself.")
    a("")

    a("## 5. Honest gaps (unattested)")
    unattested = passport.get("unattested_fields", [])
    if unattested:
        for u in unattested:
            a(f"- `{u}`")
    else:
        a("- None — all data-provenance fields are backed by recorded evidence.")

    lines.append(AUDIT_READY_FOOTER)
    return "\n".join(lines)


register(
    Pack(
        name="gdpr",
        tier="pro",
        title="GDPR — DPIA & Art. 30 record",
        description="DPIA skeleton + Art. 30 processing record from data-provenance evidence.",
        render=render,
    )
)
