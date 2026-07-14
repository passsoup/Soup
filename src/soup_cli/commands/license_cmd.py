"""soup license — activate / status / deactivate paid features (offline).

Activation verifies a signed license file against the baked-in issuer public key
and stores it at ``~/.soup/license.key``. No network — this is what makes the
paid tier usable in an air-gapped environment.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from soup_cli.passport import exit_codes, licensing

console = Console()

app = typer.Typer(no_args_is_help=True, help="Activate and inspect your Soup license (offline).")


@app.command("activate")
def activate_cmd(
    license_file: str = typer.Argument(..., help="Path to the signed license file."),
) -> None:
    """Verify a license file (offline) and activate paid features.

    Example:

        soup license activate acme.license.key
    """
    try:
        lic = licensing.activate(license_file)
    except licensing.LicenseError as exc:
        console.print(f"[red]✘ {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.CHECK_FAILED)

    console.print(f"[green]✔ activated[/] — {escape(lic.org_id)} ({escape(lic.tier)})")
    console.print(f"  expires: {escape(str(lic.expires_at))}")
    console.print(f"  features: {escape(', '.join(sorted(lic.effective_features())))}")
    if lic.adopt_credits is not None:
        console.print(f"  adopt credits: {licensing.remaining_adopt_credits(lic)}")


@app.command("status")
def status_cmd(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Show the active license: tier, expiry, permitted features."""
    lic = licensing.load_active_license()
    if lic is None:
        if json_output:
            console.print('{"active": false}', highlight=False)
        else:
            console.print("[yellow]No active license.[/] Free features only.")
            console.print("[dim]Activate with: soup license activate <file>[/]")
        raise typer.Exit(exit_codes.OK)

    if json_output:
        import json as _json

        console.print(_json.dumps({"active": True, **lic.to_public_dict()}), highlight=False)
        return

    table = Table(show_header=False, box=None)
    table.add_row("org", escape(lic.org_id))
    table.add_row("tier", escape(lic.tier))
    table.add_row("expires", escape(str(lic.expires_at)))
    table.add_row("adopt credits", escape(str(licensing.remaining_adopt_credits(lic))))
    table.add_row("features", escape(", ".join(sorted(lic.effective_features()))))
    console.print(table)


@app.command("deactivate")
def deactivate_cmd() -> None:
    """Remove the active license from this machine."""
    if licensing.deactivate():
        console.print("[green]✔ license removed.[/]")
    else:
        console.print("[yellow]No license was active.[/]")
