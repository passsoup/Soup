"""soup verify — verify a Model Passport's signature + hash chain (Free, always).

This is the viral surface. It works without a license, forever, and reuses the
exact same verification core (`soup_cli.passport.crypto.verify_passport`) that the
``/verify`` web page reimplements — so the CLI and the browser agree byte-for-byte.

Exit codes: 0 = VALID, 4 = INVALID.
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from soup_cli.passport import crypto, exit_codes
from soup_cli.passport.io import load_passport

console = Console()


def verify(
    passport: str = typer.Argument(..., help="Path to the passport JSON to verify."),
    key: Optional[str] = typer.Option(
        None, "--key", help="Trusted public key (base64 raw ed25519) the signer must match."
    ),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable result."),
) -> None:
    """Verify a passport. Green if the signature is valid and content is unchanged.

    Example:

        soup verify passport.json
        soup verify passport.json --key <base64-pubkey>   # pin a trusted signer
    """
    try:
        doc = load_passport(passport)
    except (OSError, ValueError) as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    trusted = None
    if key:
        # Accept either a raw base64 key or a path to a file containing one.
        from pathlib import Path

        kp = Path(key)
        trusted = kp.read_text(encoding="utf-8").strip() if kp.is_file() else key

    result = crypto.verify_passport(doc, trusted_public_key_b64=trusted)

    if json_output:
        import json as _json

        console.print(_json.dumps(result.to_dict()), highlight=False)
        raise typer.Exit(exit_codes.OK if result.valid else exit_codes.CHECK_FAILED)

    if result.valid:
        who = result.signer_label or (
            "the signer's personal key" if result.signer_type == "self" else "an organisation key"
        )
        body = (
            f"[bold green]✔ VALID[/] — signature is correct, content is unchanged.\n\n"
            f"[dim]model:[/] {escape(str(result.model_name))} "
            f"v{escape(str(result.model_version))}\n"
            f"[dim]signed by:[/] {escape(str(who))} "
            f"([dim]{escape(str(result.signer_type))}[/])\n"
            f"[dim]provenance:[/] {escape(str(result.provenance_class))}\n"
            f"[dim]gate verdict:[/] {escape(str(result.gate_verdict))}"
        )
        console.print(Panel(body, border_style="green", title="passport verification"))
        if result.unattested_fields:
            console.print(
                f"[yellow]{len(result.unattested_fields)} field(s) are unattested[/] "
                "(honestly not proven — see `soup passport show`)."
            )
    else:
        reasons = "\n".join(f"[red]•[/] {escape(r)}" for r in result.reasons) or "unknown"
        console.print(
            Panel(
                f"[bold red]✘ INVALID[/]\n\n{reasons}",
                border_style="red",
                title="passport verification",
            )
        )

    # The honesty disclaimer (Rule §3): math, not trust; audit-ready, not compliant.
    console.print(
        "[dim]This confirms the signature is mathematically valid and the content "
        "is unchanged. It does not certify trust in the signing key and is not a "
        "statement of regulator recognition. Audit-ready evidence, not a "
        "compliance guarantee.[/]"
    )
    raise typer.Exit(exit_codes.OK if result.valid else exit_codes.CHECK_FAILED)
