"""model-card pack (Free) — the industry-standard model card.

This is the free pack that exercises the whole rendering pipeline and gives every
Soup user something useful out of the box. It maps the passport onto the familiar
model-card sections (identity, intended use, training data, evaluation, security,
limitations).
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
    lines = header(passport, f"Model Card — {field(passport, 'model.name')}")
    a = lines.append

    bm = field(passport, "blocks.identity.base_model", {}) or {}
    a("## Model details")
    a(f"- **Base model:** {bm.get('name') or NOT_ATTESTED}")
    a(f"- **Base model hash:** `{bm.get('hash') or NOT_ATTESTED}`")
    a(f"- **Base model license:** {bm.get('license') or NOT_ATTESTED}")
    obligations = bm.get("derivative_obligations") or []
    if obligations:
        a(f"- **Derivative obligations:** {', '.join(obligations)}")
    a("")

    a("## Training data")
    datasets = field(passport, "blocks.data_provenance.datasets", []) or []
    if datasets:
        for ds in datasets:
            a(
                f"- `{ds.get('name')}` — hash `{ds.get('hash')}` "
                f"({ds.get('size_bytes')} bytes)"
            )
    else:
        a(f"- {NOT_ATTESTED}")
    pii = field(passport, "blocks.data_provenance.pii_scan", {}) or {}
    a(f"- **PII scan:** {pii.get('status', 'unattested')}")
    a("")

    tr = field(passport, "blocks.training_record", {}) or {}
    a("## Training procedure")
    a(f"- **Method:** {tr.get('method') or NOT_ATTESTED}")
    a(f"- **Duration (s):** {na(tr.get('duration_seconds'))}")
    hp = tr.get("hyperparameters") or {}
    if hp:
        a(f"- **Hyperparameters:** {', '.join(f'{k}={v}' for k, v in sorted(hp.items()))}")
    env = tr.get("environment", {}) or {}
    a(f"- **Environment:** python {env.get('python')}, cuda {env.get('cuda')}")
    a("")

    a("## Evaluation")
    scores = field(passport, "blocks.evaluation.scores", {}) or {}
    if scores:
        a("| Task | Before | After | Delta | Regression |")
        a("|---|---|---|---|---|")
        for task, s in sorted(scores.items()):
            if isinstance(s, dict):
                a(
                    f"| {task} | {s.get('before')} | {s.get('after')} | "
                    f"{s.get('delta')} | {s.get('regression')} |"
                )
    else:
        a(NOT_ATTESTED)
    verdict = field(passport, "blocks.evaluation.gate_verdict")
    a(f"\n- **Ship gate verdict:** {verdict or NOT_ATTESTED}")
    a("")

    sec = field(passport, "blocks.security", {}) or {}
    a("## Safety & security")
    a(f"- **Artifact integrity:** {sec.get('integrity', 'unattested')}")
    backdoor = field(passport, "blocks.security.backdoor_scan.status", "unattested")
    a(f"- **Backdoor scan:** {backdoor}")
    a("")

    a("## Limitations & honest gaps")
    unattested = passport.get("unattested_fields", [])
    if unattested:
        a("The following fields are **not attested** by this passport's evidence:")
        for u in unattested:
            a(f"- `{u}`")
    else:
        a("- All passport fields are backed by recorded evidence.")
    a("")

    lines.append(AUDIT_READY_FOOTER)
    return "\n".join(lines)


register(
    Pack(
        name="model-card",
        tier="free",
        title="Model Card",
        description="Industry-standard model card (identity, data, training, eval, safety).",
        render=render,
    )
)
