"""eu-ai-act-highrisk pack (Enterprise) — Annex IV technical documentation.

Organises the passport into the shape of the EU AI Act's Annex IV technical
documentation for high-risk AI systems. Audit-ready evidence; not a declaration
of conformity and not a notified-body assessment.
"""

from __future__ import annotations

from soup_cli.passport.packs.base import (
    AUDIT_READY_FOOTER,
    NOT_ATTESTED,
    Pack,
    field,
    header,
    na,
    register,
)


def render(passport: dict) -> str:
    lines = header(passport, "EU AI Act — Annex IV Technical Documentation (audit-ready)")
    a = lines.append
    model = passport.get("model", {})

    a("> Structured to the headings of Annex IV (technical documentation for "
      "high-risk AI systems). It assembles verifiable evidence from the Model "
      "Passport; conformity assessment remains the provider's responsibility.")
    a("")

    a("## 1. General description of the AI system")
    a(f"- **System / model:** {model.get('name')} v{model.get('version')}")
    a(f"- **Provider signature:** "
      f"{field(passport, 'blocks.accountability.signer.label') or 'self-signed'}")
    a(f"- **Provenance class:** {passport.get('provenance_class')}")
    a("")

    a("## 2. Detailed description of elements & development process")
    tr = field(passport, "blocks.training_record", {}) or {}
    bm = field(passport, "blocks.identity.base_model", {}) or {}
    a(f"- **Base model:** {bm.get('name') or NOT_ATTESTED} (`{bm.get('hash') or 'n/a'}`)")
    a(f"- **Development method:** {tr.get('method') or NOT_ATTESTED}")
    a(f"- **Compute / hardware:** {tr.get('hardware') or NOT_ATTESTED}")
    a(f"- **Duration (s):** {na(tr.get('duration_seconds'))}")
    a("")

    a("## 3. Data & data governance")
    datasets = field(passport, "blocks.data_provenance.datasets", []) or []
    if datasets:
        for ds in datasets:
            a(f"- `{ds.get('name')}` — `{ds.get('hash')}` ({ds.get('size_bytes')} bytes)")
    else:
        a(f"- {NOT_ATTESTED}")
    a(f"- **PII scan:** {field(passport, 'blocks.data_provenance.pii_scan.status', 'unattested')}")
    a("")

    a("## 4. Performance metrics & test results")
    scores = field(passport, "blocks.evaluation.scores", {}) or {}
    if scores:
        a("| Task | Score (after) | Delta | Regression |")
        a("|---|---|---|---|")
        for task, s in sorted(scores.items()):
            if isinstance(s, dict):
                a(f"| {task} | {s.get('after')} | {s.get('delta')} | {s.get('regression')} |")
    else:
        a(NOT_ATTESTED)
    verdict = field(passport, "blocks.evaluation.gate_verdict")
    a(f"\n- **Ship gate verdict:** {verdict or NOT_ATTESTED}")
    a("")

    a("## 5. Risk management & robustness")
    a(f"- **Artifact integrity:** {field(passport, 'blocks.security.integrity', 'unattested')}")
    a(f"- **Backdoor / tampering scan:** "
      f"{field(passport, 'blocks.security.backdoor_scan.status', 'unattested')}")
    a("")

    a("## 6. Post-market monitoring")
    a("- Re-run `soup eval` against the production baseline on each refresh; gate "
      "with `--no-regressions`.")
    a("- Re-verify the signature (`soup verify`) at each deployment to confirm the "
      "shipped artefact matches this documentation.")
    a("")

    a("## 7. Honest gaps (unattested)")
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
        name="eu-ai-act-highrisk",
        tier="enterprise",
        title="EU AI Act — Annex IV (high-risk)",
        description="Annex IV technical documentation for high-risk AI systems.",
        render=render,
    )
)
