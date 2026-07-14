"""soup pack — render a passport into a regulator/buyer document (Free/Pro/Ent).

`model-card` is free; paid packs are license-gated (feature `pack:<name>`).
One passport, many documents — a new regulation is a new renderer, not a new
product. Output is Markdown by default, PDF when reportlab is available.
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from soup_cli.passport import exit_codes, licensing
from soup_cli.passport.io import load_passport
from soup_cli.passport.packs import all_packs, get_pack

console = Console()

app = typer.Typer(no_args_is_help=True, help="Render a passport into regulator/buyer packs.")


@app.command("list")
def list_cmd() -> None:
    """List available packs and their tiers."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("pack")
    table.add_column("tier")
    table.add_column("document")
    for p in all_packs():
        tier_style = {"free": "green", "pro": "cyan", "enterprise": "magenta"}.get(p.tier, "")
        table.add_row(escape(p.name), f"[{tier_style}]{p.tier}[/]", escape(p.description))
    console.print(table)


@app.command("render")
def render_cmd(
    pack: str = typer.Option(..., "--pack", help="Pack name (see `soup pack list`)."),
    passport: str = typer.Option(..., "--passport", help="Passport JSON to render from."),
    out: Optional[str] = typer.Option(None, "--out", help="Output file (default: stdout)."),
    fmt: str = typer.Option("md", "--format", help="Output format: md | pdf."),
) -> None:
    """Render <pack> from <passport>. Paid packs need a covering license.

    Example:

        soup pack render --pack model-card --passport passport.json --out card.md
        soup pack render --pack eu-ai-act-gpai --passport passport.json --out gpai.md
    """
    try:
        pack_obj = get_pack(pack)
    except KeyError:
        names = ", ".join(p.name for p in all_packs())
        console.print(f"[red]unknown pack {escape(pack)!r}. Available: {escape(names)}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    # License gate for paid packs (model-card is free).
    feature = pack_obj.feature_key()
    if feature:
        try:
            licensing.require(feature)
        except licensing.LicenseError as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
            raise typer.Exit(exit_codes.LICENSE_REQUIRED)

    try:
        doc = load_passport(passport)
    except (OSError, ValueError) as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    try:
        markdown = pack_obj.render(doc)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]render failed: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    if fmt == "pdf":
        if not out:
            console.print("[red]--format pdf requires --out <file.pdf>[/]")
            raise typer.Exit(exit_codes.BAD_ARGS)
        try:
            _markdown_to_pdf(markdown, out)
        except (RuntimeError, ValueError) as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
            raise typer.Exit(exit_codes.ERROR)
        console.print(f"[green]✔ rendered[/] {escape(pack)} -> {escape(out)} (pdf)")
        return

    if out:
        from soup_cli.utils.paths import atomic_write_text

        try:
            written = atomic_write_text(markdown, out, prefix=".pack.", suffix=".md.tmp")
        except (OSError, ValueError) as exc:
            console.print(f"[red]could not write: {escape(str(exc))}[/]")
            raise typer.Exit(exit_codes.ERROR)
        console.print(f"[green]✔ rendered[/] {escape(pack)} -> {escape(written)}")
    else:
        print(markdown)


def _markdown_to_pdf(markdown: str, out_path: str) -> None:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError as exc:
        raise RuntimeError("PDF needs reportlab: pip install 'soup-cli[pdf]'") from exc
    from rich.markup import escape as _esc

    from soup_cli.utils.paths import enforce_under_cwd_and_no_symlink

    enforce_under_cwd_and_no_symlink(out_path, "pdf")
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out_path, pagesize=letter)
    story = []
    for line in markdown.splitlines():
        if not line.strip():
            story.append(Spacer(1, 6))
            continue
        style = "Heading1" if line.startswith("# ") else (
            "Heading2" if line.startswith("## ") else "BodyText"
        )
        story.append(Paragraph(_esc(line.lstrip("# ").replace("`", "")), styles[style]))
    doc.build(story)
