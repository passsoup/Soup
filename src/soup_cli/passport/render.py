"""Human-readable passport renderers — Rich (terminal), Markdown, and PDF.

The canonical passport is JSON; these are the *views* an auditor reads. The PDF
path is optional (reportlab lives in the ``[pdf]`` extra) and degrades to a clear
message rather than a crash when unavailable.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table


def render_terminal(passport: dict[str, Any], console: Console) -> None:
    """Pretty-print a passport's seven blocks for a human reader."""
    model = passport.get("model", {})
    prov = passport.get("provenance_class", "?")
    signer = passport.get("blocks", {}).get("accountability", {}).get("signer", {})
    signer_label = signer.get("label") or signer.get("type") or "self"

    header = (
        f"[bold]{escape(str(model.get('name')))}[/]  v{escape(str(model.get('version')))}\n"
        f"[dim]provenance:[/] {escape(prov)}   "
        f"[dim]signed by:[/] {escape(str(signer_label))}   "
        f"[dim]created:[/] {escape(str(model.get('created_at')))}"
    )
    console.print(Panel(header, title="Soup Model Passport", border_style="cyan"))

    blocks = passport.get("blocks", {})
    unattested = set(passport.get("unattested_fields", []))

    # Identity
    bm = blocks.get("identity", {}).get("base_model", {})
    console.print("[bold]1 · Identity[/]")
    console.print(f"   base model: {escape(str(bm.get('name')))}")
    console.print(f"   base hash:  [dim]{escape(str(bm.get('hash')))}[/]")
    if bm.get("license"):
        console.print(f"   base license: {escape(str(bm.get('license')))}")

    # Data provenance
    console.print("[bold]2 · Data provenance[/]")
    datasets = blocks.get("data_provenance", {}).get("datasets", [])
    if datasets:
        for ds in datasets:
            console.print(
                f"   dataset: {escape(str(ds.get('name')))} "
                f"[dim]{escape(str(ds.get('hash')))}[/]"
            )
    else:
        console.print("   [dim]datasets: unattested[/]")

    # Training record
    tr = blocks.get("training_record", {})
    console.print("[bold]3 · Training record[/]")
    console.print(
        f"   method: {escape(str(tr.get('method')))}   "
        f"duration: {escape(str(tr.get('duration_seconds')))}s"
    )
    env = tr.get("environment", {})
    console.print(
        f"   python {escape(str(env.get('python')))}  cuda {escape(str(env.get('cuda')))}"
    )

    # Evaluation
    ev = blocks.get("evaluation", {})
    console.print("[bold]4 · Evaluation[/]")
    scores = ev.get("scores", {})
    if scores:
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("task")
        table.add_column("after", justify="right")
        table.add_column("delta", justify="right")
        for task, s in sorted(scores.items()):
            if not isinstance(s, dict):
                continue
            delta = s.get("delta")
            table.add_row(
                escape(task),
                str(s.get("after")),
                "—" if delta is None else f"{delta:+g}",
            )
        console.print(table)
    verdict = ev.get("gate_verdict")
    style = "green" if verdict == "SHIP" else ("red" if verdict else "dim")
    console.print(f"   gate: [{style}]{escape(str(verdict))}[/]")

    # Security
    sec = blocks.get("security", {})
    console.print("[bold]5 · Security[/]")
    console.print(
        f"   integrity: {escape(str(sec.get('integrity')))}   "
        f"backdoor scan: {escape(str(sec.get('backdoor_scan', {}).get('status')))}"
    )

    # Accountability
    acc = blocks.get("accountability", {})
    console.print("[bold]6 · Accountability[/]")
    console.print(
        f"   run by: {escape(str(acc.get('run_by')))}   "
        f"signed at: {escape(str(acc.get('signed_at')))}"
    )

    # Lineage
    lin = blocks.get("lineage", {})
    console.print("[bold]7 · Lineage[/]")
    parent = lin.get("parent_passport_hash")
    console.print(f"   parent: [dim]{escape(str(parent)) if parent else 'none (root)'}[/]")

    if unattested:
        console.print()
        console.print(
            Panel(
                "\n".join(f"• {escape(u)}" for u in sorted(unattested)),
                title="[yellow]unattested (not proven)[/]",
                border_style="yellow",
            )
        )

    console.print(
        f"\n[dim]root hash: {escape(str(passport.get('hash_chain', {}).get('root_hash')))}[/]"
    )


def render_markdown(passport: dict[str, Any]) -> str:
    """Render a passport as a Markdown document (used by `passport show --md`)."""
    model = passport.get("model", {})
    blocks = passport.get("blocks", {})
    lines: list[str] = []
    a = lines.append
    a(f"# Model Passport — {model.get('name')} v{model.get('version')}")
    a("")
    a(f"- **Provenance class:** {passport.get('provenance_class')}")
    a(f"- **Created:** {model.get('created_at')}")
    signer = blocks.get("accountability", {}).get("signer", {})
    a(f"- **Signed by:** {signer.get('label') or signer.get('type') or 'self'}")
    a(f"- **Root hash:** `{passport.get('hash_chain', {}).get('root_hash')}`")
    a("")

    bm = blocks.get("identity", {}).get("base_model", {})
    a("## 1 · Identity")
    a(f"- Base model: `{bm.get('name')}`")
    a(f"- Base hash: `{bm.get('hash')}`")
    a(f"- Base license: {bm.get('license') or '_unattested_'}")
    a("")

    a("## 2 · Data provenance")
    datasets = blocks.get("data_provenance", {}).get("datasets", [])
    if datasets:
        for ds in datasets:
            a(f"- `{ds.get('name')}` — `{ds.get('hash')}` ({ds.get('size_bytes')} bytes)")
    else:
        a("- _datasets: unattested_")
    a("")

    tr = blocks.get("training_record", {})
    a("## 3 · Training record")
    a(f"- Method: {tr.get('method')}")
    a(f"- Duration: {tr.get('duration_seconds')} s")
    env = tr.get("environment", {})
    a(f"- Environment: python {env.get('python')}, cuda {env.get('cuda')}")
    a("")

    ev = blocks.get("evaluation", {})
    a("## 4 · Evaluation")
    a("| task | before | after | delta | regression |")
    a("|---|---|---|---|---|")
    for task, s in sorted((ev.get("scores") or {}).items()):
        if isinstance(s, dict):
            a(
                f"| {task} | {s.get('before')} | {s.get('after')} | "
                f"{s.get('delta')} | {s.get('regression')} |"
            )
    a(f"\n- **Gate verdict:** {ev.get('gate_verdict')}")
    a("")

    sec = blocks.get("security", {})
    a("## 5 · Security")
    a(f"- Integrity: {sec.get('integrity')}")
    a(f"- Backdoor scan: {sec.get('backdoor_scan', {}).get('status')}")
    a("")

    acc = blocks.get("accountability", {})
    a("## 6 · Accountability")
    a(f"- Run by: {acc.get('run_by')}")
    a(f"- Signed at: {acc.get('signed_at')}")
    a("")

    a("## 7 · Lineage")
    parent = blocks.get("lineage", {}).get("parent_passport_hash")
    a(f"- Parent passport: `{parent}`" if parent else "- Parent passport: none (root)")
    a("")

    unattested = passport.get("unattested_fields", [])
    if unattested:
        a("## Unattested fields (not proven)")
        for u in unattested:
            a(f"- `{u}`")
        a("")

    a("---")
    a(
        "_This passport records evidence captured by Soup. Verification with "
        "`soup verify` confirms the signature is mathematically valid and the "
        "content is unchanged. It is **audit-ready** evidence; it is not a "
        "certification and does not assert regulator recognition._"
    )
    return "\n".join(lines)


def render_pdf(passport: dict[str, Any], out_path: str) -> str:
    """Render a passport to a simple PDF. Raises RuntimeError if reportlab absent."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError as exc:
        raise RuntimeError(
            "PDF rendering needs reportlab: pip install 'soup-cli[pdf]'"
        ) from exc

    from soup_cli.utils.paths import enforce_under_cwd_and_no_symlink

    enforce_under_cwd_and_no_symlink(out_path, "pdf")
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out_path, pagesize=letter)
    story = []
    md = render_markdown(passport)
    for line in md.splitlines():
        if not line.strip():
            story.append(Spacer(1, 6))
            continue
        style = "Heading1" if line.startswith("# ") else (
            "Heading2" if line.startswith("## ") else "BodyText"
        )
        text = line.lstrip("# ").replace("`", "")
        story.append(Paragraph(escape(text), styles[style]))
    doc.build(story)
    return out_path
