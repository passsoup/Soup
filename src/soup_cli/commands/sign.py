"""soup sign --org — sign a passport with an organisation identity key (Pro).

So a third party verifying the passport sees "signed by MePlay Corp" instead of a
personal key. Gated by a valid license (feature ``org-signing``). Fully offline;
Enterprise can point ``--hsm`` at a PKCS#11 backend.
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape

from soup_cli.passport import crypto, exit_codes, licensing
from soup_cli.passport.io import load_passport, save_passport
from soup_cli.passport.signers import get_signer


def sign(
    passport: str = typer.Argument(..., help="Passport JSON to (re)sign with the org key."),
    org: str = typer.Option(..., "--org", help="Organisation label to embed, e.g. 'MePlay Corp'."),
    key: Optional[str] = typer.Option(
        None, "--key", help="Org private-key PEM (file backend). Generated if --generate-key."
    ),
    hsm: Optional[str] = typer.Option(
        None, "--hsm", help="PKCS#11/HSM backend config (Enterprise integration)."
    ),
    backend: str = typer.Option("file", "--backend", help="Signing backend: file | pkcs11."),
    generate_key: bool = typer.Option(
        False, "--generate-key", help="Generate a fresh org key and write it to --key."
    ),
    out: Optional[str] = typer.Option(None, "--out", help="Output path (default: overwrite)."),
) -> None:
    """Re-sign a passport with the organisation's identity key (Pro).

    Example:

        soup sign passport.json --org "MePlay Corp" --key meplay_org.pem
    """
    console = Console()

    # Paid-feature gate — exit 3 without a covering license.
    try:
        licensing.require("org-signing")
    except licensing.LicenseError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.LICENSE_REQUIRED)

    if not crypto.is_available():
        console.print("[red]Signing needs 'cryptography': pip install 'soup-cli[sign]'[/]")
        raise typer.Exit(exit_codes.ERROR)

    try:
        doc = load_passport(passport)
    except (OSError, ValueError) as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    # Resolve the signing backend.
    try:
        if backend == "file" and generate_key:
            if not key:
                console.print("[red]--generate-key requires --key <path to write>[/]")
                raise typer.Exit(exit_codes.BAD_ARGS)
            signer = _generate_and_persist_file_key(key)
        else:
            signer = get_signer(backend, key_path=key, hsm=hsm)
    except (ValueError, NotImplementedError, OSError) as exc:
        console.print(f"[red]signer error: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    try:
        crypto.sign_passport_with_signer(doc, signer, signer_type="org", signer_label=org)
    except NotImplementedError as exc:
        console.print(f"[yellow]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    dest = out or passport
    try:
        written = save_passport(doc, dest)
    except (OSError, ValueError) as exc:
        console.print(f"[red]could not write passport: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    console.print(f"[green]✔ signed by {escape(org)}[/] -> {escape(written)}")
    console.print(f"  org public key: [dim]{escape(doc['signature']['public_key'])}[/]")
    console.print(
        "[dim]Verifiers see this org label as a claim; `soup verify` proves the "
        "signature is valid, not that the key is trusted.[/]"
    )


def _generate_and_persist_file_key(key_path: str):
    """Generate an ed25519 org key, write it 0600, return a FileSigner over it."""
    import os

    from soup_cli.passport.crypto import _private_pem, generate_private_key
    from soup_cli.passport.signers import FileSigner

    priv = generate_private_key()
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(_private_pem(priv))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    Console().print(f"[dim]generated org key -> {key_path} (keep it secret)[/]")
    return FileSigner(priv)
