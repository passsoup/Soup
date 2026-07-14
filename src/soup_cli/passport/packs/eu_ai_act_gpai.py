"""eu-ai-act-gpai pack (Pro) — GPAI provider technical documentation.

Maps the passport onto the shape of the EU AI Act's obligations for providers of
general-purpose AI models: provider technical documentation, the downstream
information package, and a public summary of training content (the Commission's
template). Note: substantially modifying an open model can itself make you a GPAI
provider — this pack helps you be ready for that.

Audit-ready wording only; nothing here claims compliance or Commission review.
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
    lines = header(passport, "EU AI Act — GPAI Provider Documentation (audit-ready draft)")
    a = lines.append

    a("> **Scope.** This document organises the passport's verifiable evidence "
      "into the sections a provider of a general-purpose AI model prepares under "
      "the EU AI Act (Arts. 53–55 and Annexes). It is audit-ready evidence, not a "
      "declaration of conformity.")
    a("")

    a("## 1. General information")
    model = passport.get("model", {})
    provider = field(passport, "blocks.accountability.signer.label") or "self-signed"
    a(f"- **Model name / version:** {model.get('name')} v{model.get('version')}")
    a(f"- **Provider signature:** {provider}")
    a(f"- **Provenance class:** {passport.get('provenance_class')}")
    a("")

    a("## 2. Model architecture & base model")
    bm = field(passport, "blocks.identity.base_model", {}) or {}
    a(f"- **Base model:** {bm.get('name') or NOT_ATTESTED} (hash `{bm.get('hash') or 'n/a'}`)")
    a(f"- **Base model licence & derivative obligations:** {bm.get('license') or NOT_ATTESTED}")
    obligations = bm.get("derivative_obligations") or []
    if obligations:
        for o in obligations:
            a(f"  - {o}")
    a("")

    a("## 3. Training process (technical documentation)")
    tr = field(passport, "blocks.training_record", {}) or {}
    a(f"- **Method:** {tr.get('method') or NOT_ATTESTED}")
    a(f"- **Compute / hardware:** {tr.get('hardware') or NOT_ATTESTED}")
    a(f"- **Duration (s):** {na(tr.get('duration_seconds'))}")
    env = tr.get("environment", {}) or {}
    n_libs = len(env.get("libraries", {}) or {})
    a(f"- **Reproducibility environment:** python {env.get('python')}, "
      f"cuda {env.get('cuda')}, {n_libs} pinned libraries")
    a("")

    a("## 4. Public summary of training content")
    a("_Commission-template public summary, assembled from dataset fingerprints "
      "in the passport. Raw data is never included — only hashes and sources._")
    datasets = field(passport, "blocks.data_provenance.datasets", []) or []
    if datasets:
        a("")
        a("| Dataset | Source | Hash | Size (bytes) |")
        a("|---|---|---|---|")
        for ds in datasets:
            a(f"| {ds.get('name')} | {ds.get('source')} | "
              f"`{ds.get('hash')}` | {ds.get('size_bytes')} |")
    else:
        a(f"- {NOT_ATTESTED}")
    legality = field(passport, "blocks.data_provenance.origin_legality")
    pii = field(passport, "blocks.data_provenance.pii_scan.status", "unattested")
    a(f"\n- **Data origin legality:** {legality or NOT_ATTESTED}")
    a(f"- **PII scan:** {pii}")
    a("")

    a("## 5. Evaluation & testing")
    scores = field(passport, "blocks.evaluation.scores", {}) or {}
    if scores:
        a("| Capability / task | Score (after) | Regression vs baseline |")
        a("|---|---|---|")
        for task, s in sorted(scores.items()):
            if isinstance(s, dict):
                a(f"| {task} | {s.get('after')} | {s.get('regression')} |")
    else:
        a(NOT_ATTESTED)
    verdict = field(passport, "blocks.evaluation.gate_verdict")
    a(f"\n- **Ship gate verdict:** {verdict or NOT_ATTESTED}")
    a("")

    a("## 6. Risk & security controls")
    integrity = field(passport, "blocks.security.integrity", "unattested")
    backdoor = field(passport, "blocks.security.backdoor_scan.status", "unattested")
    a(f"- **Artifact integrity:** {integrity}")
    a(f"- **Backdoor / tampering scan:** {backdoor}")
    a("")

    a("## 7. Information for downstream providers")
    a("Downstream deployers integrating this model should record: the base-model "
      "licence obligations above, the evaluation results and their baseline, and "
      "the passport root hash for provenance. The signed passport (`passport.json`) "
      "is the machine-verifiable companion to this document — verify it with "
      "`soup verify` or at trysoup.dev/verify.")
    a("")

    a("## 8. Honest gaps (unattested)")
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
        name="eu-ai-act-gpai",
        tier="pro",
        title="EU AI Act — GPAI Provider Documentation",
        description="GPAI provider technical docs + downstream info + training-data summary.",
        render=render,
    )
)
