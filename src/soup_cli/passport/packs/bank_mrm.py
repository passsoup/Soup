"""bank-mrm pack (Enterprise) — US bank Model Risk Management for GenAI.

Organises the passport into the artefacts a bank's Model Risk function expects,
applying the principles of SR 26-2 (materiality, ongoing monitoring, effective
challenge) to a generative model: a development document, a validation report, a
statement of limitations, and a monitoring plan.

Audit-ready evidence for the second line of defence — not a validation sign-off.
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
    lines = header(passport, "Model Risk Management Package — GenAI (audit-ready)")
    a = lines.append

    a("> Applies the principles of the US interagency GenAI model-risk guidance "
      "(SR 26-2: materiality, ongoing monitoring, effective challenge) to this "
      "model. Assembled from a signed Model Passport; it supports validation, it "
      "is not a validation opinion.")
    a("")

    a("## A. Model development document")
    model = passport.get("model", {})
    bm = field(passport, "blocks.identity.base_model", {}) or {}
    tr = field(passport, "blocks.training_record", {}) or {}
    a(f"- **Model / version:** {model.get('name')} v{model.get('version')}")
    a(f"- **Provenance class:** {passport.get('provenance_class')}")
    a(f"- **Base model:** {bm.get('name') or NOT_ATTESTED} (`{bm.get('hash') or 'n/a'}`)")
    a(f"- **Development method:** {tr.get('method') or NOT_ATTESTED}")
    a(f"- **Training duration (s):** {na(tr.get('duration_seconds'))}")
    a(f"- **Development environment:** python "
      f"{tr.get('environment', {}).get('python')}, "
      f"cuda {tr.get('environment', {}).get('cuda')}")
    a("")

    a("## B. Data lineage & conceptual soundness")
    datasets = field(passport, "blocks.data_provenance.datasets", []) or []
    if datasets:
        for ds in datasets:
            a(f"- `{ds.get('name')}` — `{ds.get('hash')}` ({ds.get('size_bytes')} bytes)")
    else:
        a(f"- {NOT_ATTESTED}")
    a(f"- **PII scan:** {field(passport, 'blocks.data_provenance.pii_scan.status', 'unattested')}")
    a("")

    a("## C. Validation report — outcomes analysis")
    scores = field(passport, "blocks.evaluation.scores", {}) or {}
    if scores:
        a("| Test | Score (after) | Baseline | Delta | Regression |")
        a("|---|---|---|---|---|")
        for task, s in sorted(scores.items()):
            if isinstance(s, dict):
                a(f"| {task} | {s.get('after')} | {s.get('before')} | "
                  f"{s.get('delta')} | {s.get('regression')} |")
    else:
        a(NOT_ATTESTED)
    verdict = field(passport, "blocks.evaluation.gate_verdict")
    a(f"\n- **Ship gate (effective challenge outcome):** {verdict or NOT_ATTESTED}")
    a("")

    a("## D. Security & integrity controls")
    integrity = field(passport, "blocks.security.integrity", "unattested")
    backdoor = field(passport, "blocks.security.backdoor_scan.status", "unattested")
    a(f"- **Artifact integrity:** {integrity}")
    a(f"- **Backdoor / tampering scan:** {backdoor}")
    a("")

    a("## E. Statement of limitations")
    unattested = passport.get("unattested_fields", [])
    if unattested:
        a("Material limitations — the following are **not attested** by this "
          "passport and require compensating controls or manual validation:")
        for u in unattested:
            a(f"- `{u}`")
    else:
        a("- No unattested fields; all sections are backed by recorded evidence.")
    a("")

    a("## F. Ongoing monitoring plan")
    a("- Re-run `soup eval` against the production baseline on each model "
      "refresh; gate with `--no-regressions` to block silent degradation.")
    a("- Re-verify the passport signature (`soup verify`) whenever the artefact "
      "is redeployed to confirm the shipped weights match the validated record.")
    a("- Track the passport root hash in the model inventory as the immutable "
      "reference for this version.")
    a("")

    a("## G. Accountability")
    acc = field(passport, "blocks.accountability", {}) or {}
    a(f"- **Developed/run by:** {acc.get('run_by')}")
    a(f"- **Signed at:** {acc.get('signed_at')}")
    signer = acc.get("signer", {}) or {}
    a(f"- **Signing identity:** {signer.get('label') or signer.get('type') or 'self'}")
    a(f"- **Passport root hash:** `{field(passport, 'hash_chain.root_hash')}`")

    lines.append(AUDIT_READY_FOOTER)
    return "\n".join(lines)


register(
    Pack(
        name="bank-mrm",
        tier="enterprise",
        title="Bank Model Risk Management (GenAI)",
        description="US bank MRM package (SR 26-2): development, validation, monitoring.",
        render=render,
    )
)
