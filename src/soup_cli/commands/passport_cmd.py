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
