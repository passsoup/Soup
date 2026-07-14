"""nist-ai-rmf / iso-42001 packs (Enterprise) — voluntary-framework mappings.

Maps the passport onto the NIST AI Risk Management Framework functions (Govern,
Map, Measure, Manage) and, via an alias, the ISO/IEC 42001 AI-management-system
clauses that US enterprise procurement asks about. Audit-ready mapping evidence,
not a certification.
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


def _render(passport: dict, framework: str) -> str:
    lines = header(passport, f"{framework} — Mapping Evidence (audit-ready)")
    a = lines.append
    model = passport.get("model", {})

    a(f"> Maps the Model Passport onto {framework}. It evidences the technical "
      "controls; organisational governance is documented separately by the "
      "adopting organisation.")
    a("")

    a("## Govern")
    a(f"- **Model / version:** {model.get('name')} v{model.get('version')}")
    a(f"- **Accountable party:** {field(passport, 'blocks.accountability.run_by') or NOT_ATTESTED}")
    a(f"- **Signing identity:** "
      f"{field(passport, 'blocks.accountability.signer.label') or 'self-signed'}")
    a(f"- **Immutable reference:** passport root hash "
      f"`{field(passport, 'hash_chain.root_hash')}`")
    a("")

    a("## Map (context & data)")
    datasets = field(passport, "blocks.data_provenance.datasets", []) or []
    if datasets:
        for ds in datasets:
            a(f"- `{ds.get('name')}` — `{ds.get('hash')}`")
    else:
        a(f"- {NOT_ATTESTED}")
    bm = field(passport, "blocks.identity.base_model", {}) or {}
    a(f"- **Base model:** {bm.get('name') or NOT_ATTESTED}")
    a("")

    a("## Measure (evaluation & testing)")
    scores = field(passport, "blocks.evaluation.scores", {}) or {}
    if scores:
        a("| Task | Score (after) | Regression |")
        a("|---|---|---|")
        for task, s in sorted(scores.items()):
            if isinstance(s, dict):
                a(f"| {task} | {s.get('after')} | {s.get('regression')} |")
    else:
        a(NOT_ATTESTED)
    a(f"\n- **Integrity:** {field(passport, 'blocks.security.integrity', 'unattested')}")
    a(f"- **Backdoor scan:** "
      f"{field(passport, 'blocks.security.backdoor_scan.status', 'unattested')}")
    a("")

    a("## Manage (monitoring & response)")
    a(f"- **Ship gate verdict:** "
      f"{field(passport, 'blocks.evaluation.gate_verdict') or NOT_ATTESTED}")
    a("- Re-verify the signature on each deployment; re-evaluate with a "
      "no-regressions gate on each refresh.")
    a("")

    a("## Honest gaps (unattested)")
    unattested = passport.get("unattested_fields", [])
    if unattested:
        for u in unattested:
            a(f"- `{u}`")
    else:
        a("- None — all sections are backed by recorded evidence.")

    lines.append(AUDIT_READY_FOOTER)
    return "\n".join(lines)


def render_nist(passport: dict) -> str:
    return _render(passport, "NIST AI RMF")


def render_iso(passport: dict) -> str:
    return _render(passport, "ISO/IEC 42001")


register(
    Pack(
        name="nist-ai-rmf",
        tier="enterprise",
        title="NIST AI RMF mapping",
        description="Mapping onto NIST AI RMF functions (Govern/Map/Measure/Manage).",
        render=render_nist,
    )
)
register(
    Pack(
        name="iso-42001",
        tier="enterprise",
        title="ISO/IEC 42001 mapping",
        description="Mapping onto ISO/IEC 42001 AI-management-system clauses.",
        render=render_iso,
    )
)
