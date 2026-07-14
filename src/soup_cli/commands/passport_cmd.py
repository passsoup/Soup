"""soup passport — the Model Passport command group.

Subcommands:

- ``soup passport train``  record training evidence  -> .soup/train.json  (Free)
- ``soup passport eval``   run an eval suite + regressions -> .soup/eval.json (Free)
- ``soup passport build``  assemble + self-sign the passport -> passport.json (Free)
- ``soup passport show``   pretty-print a passport for a human reader        (Free)
- ``soup passport push/pull/list/serve``  passport registry                 (Pro/Ent)

``soup passport eval`` (not ``soup eval``) because the existing ``soup eval`` is
the benchmark-suite command; this one produces the passport's evidence block.
"""

from __future__ import annotations

import uuid
from typing import List, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from soup_cli.passport import exit_codes
from soup_cli.passport.environ import capture_environment, utc_now_iso
from soup_cli.passport.runstore import RunStore

console = Console()

app = typer.Typer(no_args_is_help=True, help="Model Passport: record, evaluate, assemble, verify.")


@app.command("train")
def train_cmd(
    base: str = typer.Option(..., "--base", help="Base model (local path or hub id)."),
    method: str = typer.Option("lora", "--method", help="Training method: lora | qlora | full."),
    data: List[str] = typer.Option(None, "--data", help="Dataset file/dir (repeatable)."),
    out: Optional[str] = typer.Option(None, "--out", help="Produced checkpoint (hashed)."),
    duration_seconds: Optional[float] = typer.Option(
        None, "--duration-seconds", help="Wall-clock training duration, if known."
    ),
    base_license: Optional[str] = typer.Option(None, "--base-license", help="Base model license."),
    run_dir: str = typer.Option(".soup", "--run-dir", help="Run directory for evidence."),
) -> None:
    """Record the training evidence for a run -> .soup/train.json (block 3).

    Real fine-tuning is `soup train`. This captures the *provenance*: base-model
    and dataset fingerprints, method, hardware, and the exact environment. Only
    hashes are stored — never the data or weights.

    Example:

        soup passport train --base ./base --method lora --data ./data/train.jsonl --out ./output
    """
    from soup_cli.passport.training import build_training_record

    try:
        record = build_training_record(
            base_model=base,
            method=method,
            output_path=out,
            datasets=list(data or []),
            duration_seconds=duration_seconds,
            base_license=base_license,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]could not build training record: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    store = RunStore(run_dir)
    store.ensure_run(uuid.uuid4().hex[:12], utc_now_iso(), capture_environment())
    store.write("train.json", record)

    console.print("[green]✔ recorded training evidence[/] -> .soup/train.json")
    console.print(f"  base: {escape(base)}  method: {escape(method)}")
    if record["base_model"]["hash"]:
        console.print(f"  base hash: [dim]{escape(record['base_model']['hash'])}[/]")
    for ds in record["datasets"]:
        console.print(f"  dataset: {escape(ds['name'])} [dim]{escape(str(ds.get('hash')))}[/]")


@app.command("eval")
def eval_cmd(
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Checkpoint to eval (live)."),
    suite: str = typer.Option("smoke", "--suite", help="Built-in suite name or suite JSONL path."),
    predictions: Optional[str] = typer.Option(
        None, "--predictions", help="JSONL of model outputs (replay mode; offline)."
    ),
    baseline: Optional[str] = typer.Option(
        None, "--baseline", help="Baseline passport or eval.json for regression deltas."
    ),
    regression_threshold: float = typer.Option(
        0.0, "--regression-threshold", help="A drop larger than this counts as a regression."
    ),
    max_new_tokens: int = typer.Option(32, "--max-new-tokens", help="Live-mode generation length."),
    run_dir: str = typer.Option(".soup", "--run-dir", help="Run directory for evidence."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Run an eval suite (+ regression check) -> .soup/eval.json (block 4).

    Live mode needs the training stack; replay mode (`--predictions`) is fully
    offline. Example:

        soup passport eval --model ./output --suite smoke --baseline base-passport.json
    """
    from soup_cli.passport.evaluation import evaluate, load_suite, resolve_predictions

    try:
        suite_obj = load_suite(suite)
    except (ValueError, OSError) as exc:
        console.print(f"[red]could not load suite: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    try:
        preds = resolve_predictions(
            model=model, predictions=predictions, suite=suite_obj, max_new_tokens=max_new_tokens
        )
    except (ValueError, RuntimeError) as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    result = evaluate(
        suite_obj, preds, baseline=baseline, regression_threshold=regression_threshold
    )

    RunStore(run_dir).write("eval.json", result.to_dict())

    if json_output:
        import json as _json

        console.print(_json.dumps(result.to_dict()), highlight=False)
        return

    table = Table(
        title=f"eval · suite '{escape(result.suite)}'", show_header=True, header_style="bold"
    )
    table.add_column("task")
    table.add_column("after", justify="right")
    table.add_column("before", justify="right")
    table.add_column("delta", justify="right")
    table.add_column("regression")
    for task, s in sorted(result.scores.items()):
        delta = s.get("delta")
        before = s.get("before")
        reg = s.get("regression")
        table.add_row(
            escape(task),
            f"{s['after']:.3g}",
            "—" if before is None else f"{before:.3g}",
            "—" if delta is None else f"{delta:+.3g}",
            "[red]YES[/]" if reg else "[green]no[/]",
        )
    console.print(table)
    if result.has_regressions:
        console.print("[yellow]regressions detected — gate with --no-regressions to block ship.[/]")


@app.command("build")
def build_cmd(
    name: str = typer.Option(..., "--name", help="Model name for the passport."),
    version: str = typer.Option("1.0.0", "--version", help="Model version."),
    out: str = typer.Option("passport.json", "--out", help="Output passport JSON path."),
    parent: Optional[str] = typer.Option(
        None, "--parent", help="Parent passport JSON for lineage/diff."
    ),
    pdf: Optional[str] = typer.Option(None, "--pdf", help="Also render a human-readable PDF."),
    run_dir: str = typer.Option(".soup", "--run-dir", help="Run directory with evidence."),
    key: Optional[str] = typer.Option(
        None, "--key", help="Self-sign private key PEM (default: ~/.soup/keys/id_ed25519)."
    ),
) -> None:
    """Assemble a passport from .soup evidence and self-sign it (Native class).

    Missing evidence is honestly recorded as `unattested`. Example:

        soup passport build --name acme-support-llm --version 1.3.0 --out passport.json
    """
    from soup_cli.passport import crypto
    from soup_cli.passport.builder import build_passport
    from soup_cli.passport.io import load_passport, save_passport

    if not crypto.is_available():
        console.print(
            "[red]Signing needs the 'cryptography' package: pip install 'soup-cli[sign]'[/]"
        )
        raise typer.Exit(exit_codes.ERROR)

    parent_passport = None
    if parent:
        try:
            parent_passport = load_passport(parent)
        except (OSError, ValueError) as exc:
            console.print(f"[red]could not read --parent: {escape(str(exc))}[/]")
            raise typer.Exit(exit_codes.BAD_ARGS)

    store = RunStore(run_dir)
    passport = build_passport(
        store, model_name=name, model_version=version, parent_passport=parent_passport
    )

    try:
        priv = crypto.load_private_key_pem(key) if key else crypto.load_or_create_self_key()
    except (OSError, ValueError) as exc:
        console.print(f"[red]could not load signing key: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    crypto.sign_passport(passport, priv, signer_type="self")

    try:
        written = save_passport(passport, out)
    except (OSError, ValueError) as exc:
        console.print(f"[red]could not write passport: {escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.ERROR)

    console.print(f"[green]✔ passport signed[/] -> {escape(written)}")
    console.print("  provenance: native   signer: self")
    console.print(f"  root hash: [dim]{escape(passport['hash_chain']['root_hash'])}[/]")
    if passport["unattested_fields"]:
        console.print(
            f"  [yellow]{len(passport['unattested_fields'])} unattested field(s)[/] "
            "(honest gaps — run more evidence commands to close them)"
        )

    if pdf:
        from soup_cli.passport.render import render_pdf

        try:
            render_pdf(passport, pdf)
            console.print(f"  pdf: {escape(pdf)}")
        except (RuntimeError, ValueError) as exc:
            console.print(f"[yellow]pdf skipped: {escape(str(exc))}[/]")


@app.command("show")
def show_cmd(
    passport: str = typer.Argument(..., help="Passport JSON to display."),
    markdown: bool = typer.Option(False, "--md", help="Emit Markdown instead of a terminal view."),
) -> None:
    """Pretty-print a passport's seven blocks for a human reader."""
    from soup_cli.passport.io import load_passport
    from soup_cli.passport.render import render_markdown, render_terminal

    try:
        doc = load_passport(passport)
    except (OSError, ValueError) as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(exit_codes.BAD_ARGS)

    if markdown:
        print(render_markdown(doc))
    else:
        render_terminal(doc, console)
