"""soup adopt — onboard a model trained outside Soup → an Attested passport (paid).

"Train anywhere. The passport is Soup's." We can only attest what is re-checkable
after the fact: a deep integrity/backdoor scan, and evals we can run now. Anything
we cannot verify (how it was trained, on what data) is honestly marked
``unattested``. That honesty is the feature, and it is printed on the passport.

Gated by the ``adopt`` license feature; consumes one BYOM credit per model.
"""

from __future__ import annotations

import uuid
from typing import List, Optional

import typer
from rich.console import Console
from rich.markup import escape

from soup_cli.passport import crypto, exit_codes, licensing
from soup_cli.passport.environ import capture_environment, utc_now_iso
from soup_cli.passport.runstore import RunStore
from soup_cli.passport.schema import PROVENANCE_ATTESTED

console = Console()


def adopt(
    checkpoint: str = typer.Argument(..., help="Path to the external checkpoint to adopt."),
    name: Optional[str] = typer.Option(None, "--name", help="Model name (default: dir name)."),
    version: str = typer.Option("1.0.0", "--version", help="Model version."),
    data: List[str] = typer.Option(None, "--data", help="Dataset to fingerprint, if on hand."),
    suite: Optional[str] = typer.Option(None, "--suite", help="Eval suite name or JSONL path."),
    predictions: Optional[str] = typer.Option(
        None, "--predictions", help="Model outputs JSONL (offline replay eval)."
    ),
    out: str = typer.Option("passport.json", "--out", help="Output passport path."),
    run_dir: str = typer.Option(".soup", "--run-dir", help="Run directory for evidence."),
) -> None:
    """Deep-scan + eval an external model and emit an Attested passport (paid).

    Example:

        soup adopt ./external-model --name vendor-llm --suite smoke --predictions p.jsonl
    """
    # Paid-feature gate.
    try:
        licensing.require("adopt")
    except licensing.LicenseError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.LICENSE_REQUIRED)

    if not crypto.is_available():
        console.print("[red]Signing needs 'cryptography': pip install 'soup-cli[sign]'[/]")
        raise typer.Exit(exit_codes.ERROR)

    from pathlib import Path

    ckpt = Path(checkpoint)
    if not ckpt.exists():
        console.print(f"[red]checkpoint not found: {escape(checkpoint)}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)
    model_name = name or ckpt.name

    store = RunStore(run_dir)
    store.ensure_run(uuid.uuid4().hex[:12], utc_now_iso(), capture_environment())

    # 1. Deep scan (integrity + backdoor) — always runs.
    from soup_cli.passport.scanning import scan_checkpoint

    console.print(f"[dim]scanning {escape(checkpoint)} (deep)…[/]")
    scan_result = scan_checkpoint(checkpoint, deep=True)
    store.write("scan.json", scan_result.to_dict())
    if not scan_result.is_clean:
        console.print(
            f"[yellow]scan flagged {len(scan_result.findings)} issue(s) — "
            "recorded in the passport (adoption continues; the finding is the value).[/]"
        )

    # 2. Fingerprint data if the operator still has it; else unattested.
    if data:
        from soup_cli.passport.training import build_training_record

        record = build_training_record(
            base_model=str(ckpt), method="external", output_path=str(ckpt), datasets=list(data)
        )
        # For an adopted model we cannot attest the base or method — keep only
        # the dataset fingerprints, which ARE re-checkable against the files.
        store.write(
            "train.json",
            {"datasets": record["datasets"], "base_model": {"name": None, "hash": None,
                                                            "license": None,
                                                            "derivative_obligations": []}},
        )

    # 3. Eval, if we can (replay or live).
    if suite or predictions:
        from soup_cli.passport.evaluation import evaluate, load_suite, resolve_predictions

        try:
            suite_obj = load_suite(suite or "smoke")
            preds = resolve_predictions(
                model=None if predictions else str(ckpt),
                predictions=predictions,
                suite=suite_obj,
            )
            result = evaluate(suite_obj, preds)
            store.write("eval.json", result.to_dict())
        except (ValueError, RuntimeError) as exc:
            console.print(f"[yellow]eval skipped ({escape(str(exc))}); left unattested.[/]")

    # 4. Build an ATTESTED passport (honest unattested fields) and sign it.
    from soup_cli.passport.builder import build_passport
    from soup_cli.passport.io import save_passport

    passport = build_passport(
        store, model_name=model_name, model_version=version,
        provenance_class=PROVENANCE_ATTESTED,
    )
    priv = crypto.load_or_create_self_key()
    crypto.sign_passport(passport, priv, signer_type="self")

    try:
        written = save_passport(passport, out)
    except (OSError, ValueError) as exc:
        console.print(f"[red]could not write passport: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    # 5. Consume one BYOM credit (unlimited licenses return None).
    try:
        remaining = licensing.decrement_adopt_credit()
    except licensing.LicenseError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.LICENSE_REQUIRED)

    console.print(f"[green]✔ adopted[/] {escape(model_name)} -> {escape(written)}")
    console.print(f"  provenance: [magenta]attested[/]   scan: {escape(scan_result.status)}")
    console.print(
        f"  [yellow]{len(passport['unattested_fields'])} unattested field(s)[/] "
        "(what could not be re-verified for an external model — printed honestly)."
    )
    if remaining is not None:
        console.print(f"  adopt credits remaining: {remaining}")
