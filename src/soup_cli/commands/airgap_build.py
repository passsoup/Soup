"""soup airgap — build a single portable offline bundle (Enterprise).

The bundle runs the whole passport pipeline on an isolated machine. Only the
build step may touch the network (to vendor wheels); the bundle itself is fully
offline. Gated by the `airgap` license feature.
"""

from __future__ import annotations

from typing import List, Optional

import typer
from rich.console import Console
from rich.markup import escape

from soup_cli.passport import exit_codes, licensing

console = Console()

app = typer.Typer(no_args_is_help=True, help="Build a portable offline air-gap bundle (Ent).")


@app.command("build")
def build_cmd(
    out: str = typer.Option("soup-airgap.tar.gz", "--out", help="Output bundle path."),
    include_wheels: bool = typer.Option(
        False, "--include-wheels", help="Vendor CLI wheels (needs network at build time)."
    ),
    license_file: Optional[str] = typer.Option(None, "--license", help="Offline license file."),
    include_models: List[str] = typer.Option(
        None, "--include-models", help="Base model path(s) to bundle (repeatable)."
    ),
) -> None:
    """Assemble an offline bundle (CLI + docs + verifier + demo + registry seed).

    Example:

        soup airgap build --out soup-airgap.tar.gz --include-wheels --license acme.license.key
    """
    try:
        licensing.require("airgap")
    except licensing.LicenseError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.LICENSE_REQUIRED)

    from soup_cli.passport.airgap import build_bundle

    console.print(f"[dim]building air-gap bundle -> {escape(out)}…[/]")
    try:
        manifest = build_bundle(
            out,
            include_wheels=include_wheels,
            license_file=license_file,
            include_models=list(include_models or []),
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]bundle build failed: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    console.print(f"[green]✔ bundle built[/] -> {escape(out)}")
    console.print(f"  contents: {escape(', '.join(manifest['contents']))}")
    console.print(f"  wheels vendored: {manifest['wheels_included']}")
    if manifest["models_included"]:
        console.print(f"  models: {escape(', '.join(manifest['models_included']))}")
    console.print(f"  sha256: [dim]{escape(manifest['bundle_sha256'])}[/]")
    console.print(
        "[dim]On the isolated machine: extract, then ./run_pipeline.sh "
        "(scan→eval→gate→passport→verify, zero network).[/]"
    )
