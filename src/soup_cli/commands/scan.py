"""soup scan — checkpoint integrity + backdoor/tamper scan (Free).

Writes ``.soup/scan.json`` (block 5 evidence) and exits 4 if a threat is found,
so CI blocks on a poisoned checkpoint. Loads no weights — pure offline analysis.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from soup_cli.passport import exit_codes
from soup_cli.passport.runstore import RunStore
from soup_cli.passport.scanning import SEV_CRITICAL, SEV_INFO, SEV_WARNING, scan_checkpoint

console = Console()

_SEV_STYLE = {SEV_CRITICAL: "bold red", SEV_WARNING: "yellow", SEV_INFO: "dim"}


def scan(
    model: str = typer.Option(..., "--model", "-m", help="Checkpoint file or directory to scan."),
    deep: bool = typer.Option(
        False, "--deep", help="Also run the weight-statistics anomaly pass (needs safetensors)."
    ),
    run_dir: str = typer.Option(".soup", "--run-dir", help="Run directory for evidence."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Scan a checkpoint for integrity + backdoors. Exit 0 clean, 4 on a finding.

    Example:

        soup scan --model ./output --deep
    """
    try:
        result = scan_checkpoint(model, deep=deep)
    except FileNotFoundError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]scan failed: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    # Persist evidence for the passport.
    try:
        RunStore(run_dir).write("scan.json", result.to_dict())
    except (OSError, ValueError) as exc:
        console.print(f"[yellow]warning: could not write scan.json: {escape(str(exc))}[/]")

    if json_output:
        import json as _json

        console.print(_json.dumps(result.to_dict()), highlight=False)
        raise typer.Exit(exit_codes.OK if result.is_clean else exit_codes.CHECK_FAILED)

    if result.is_clean:
        console.print(
            f"[bold green]✔ CLEAN[/]  {result.files_scanned} files, "
            f"integrity {escape(result.integrity)}"
        )
        if result.findings:  # info-only notes
            for f in result.findings:
                console.print(f"  [dim]· {escape(f.message)}[/]")
    else:
        console.print(
            f"[bold red]✘ FLAGGED[/]  integrity {escape(result.integrity)} "
            f"({result.files_scanned} files scanned)"
        )
        table = Table(show_header=True, header_style="bold")
        table.add_column("severity")
        table.add_column("finding")
        table.add_column("path", overflow="fold")
        for f in result.findings:
            style = _SEV_STYLE.get(f.severity, "")
            table.add_row(
                f"[{style}]{escape(f.severity)}[/]",
                escape(f.message),
                escape(f.path or ""),
            )
        console.print(table)

    console.print(f"[dim]artifact: {escape(result.artifact_hash or '')}[/]")
    raise typer.Exit(exit_codes.OK if result.is_clean else exit_codes.CHECK_FAILED)
