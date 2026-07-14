"""soup gate — binary SHIP / DON'T SHIP verdict for CI (Free).

Reads ``.soup/eval.json`` (+ optional ``.soup/scan.json``), applies rules, writes
``.soup/gate.json``, and — crucially — exits 4 on DON'T SHIP so a CI pipeline
fails. That non-zero exit is the whole point of the command.
"""

from __future__ import annotations

from typing import List, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from soup_cli.passport import exit_codes
from soup_cli.passport.gate import (
    GateRules,
    evaluate_gate,
    parse_min_score,
    rules_from_yaml,
)
from soup_cli.passport.runstore import RunStore

console = Console()


def gate(
    rules: Optional[str] = typer.Option(
        None, "--rules", help="YAML/JSON file of gate rules (min_scores, no_regressions, ...)."
    ),
    min_score: List[str] = typer.Option(
        None, "--min-score", help="Per-task floor, e.g. --min-score arithmetic=0.8 (repeatable)."
    ),
    no_regressions: bool = typer.Option(
        False, "--no-regressions", help="Fail if any task regressed against the baseline."
    ),
    require_clean_scan: bool = typer.Option(
        False, "--require-clean-scan", help="Fail unless .soup/scan.json is clean."
    ),
    run_dir: str = typer.Option(".soup", "--run-dir", help="Run directory holding evidence."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Decide SHIP / DON'T SHIP from run evidence. Exit 0 SHIP, 4 DON'T SHIP.

    Example:

        soup gate --min-score arithmetic=0.8 --no-regressions --require-clean-scan
    """
    store = RunStore(run_dir)

    # Assemble rules: YAML file first, then CLI flags override/extend it.
    gate_rules = GateRules()
    if rules:
        try:
            import yaml

            from soup_cli.utils.paths import enforce_under_cwd_and_no_symlink

            enforce_under_cwd_and_no_symlink(rules, "rules")
            with open(rules, encoding="utf-8") as fh:
                gate_rules = rules_from_yaml(yaml.safe_load(fh) or {})
        except (OSError, ValueError) as exc:
            console.print(f"[red]could not read --rules: {escape(str(exc))}[/]")
            raise typer.Exit(exit_codes.BAD_ARGS)

    if min_score:
        try:
            gate_rules.min_scores.update(parse_min_score(list(min_score)))
        except ValueError as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
            raise typer.Exit(exit_codes.BAD_ARGS)
    if no_regressions:
        gate_rules.no_regressions = True
    if require_clean_scan:
        gate_rules.require_clean_scan = True

    eval_json = store.read_optional("eval.json")
    scan_json = store.read_optional("scan.json")
    if eval_json is None and not gate_rules.require_clean_scan and not gate_rules.min_scores:
        console.print(
            "[yellow]No eval evidence (.soup/eval.json) and no rules given — "
            "nothing to gate on. Run `soup passport eval` first.[/]"
        )

    result = evaluate_gate(eval_json, scan_json, gate_rules)

    try:
        store.write("gate.json", result.to_dict())
    except (OSError, ValueError) as exc:
        console.print(f"[yellow]warning: could not write gate.json: {escape(str(exc))}[/]")

    if json_output:
        import json as _json

        console.print(_json.dumps(result.to_dict()), highlight=False)
        raise typer.Exit(result.exit_code)

    if result.ship:
        console.print(Panel.fit("[bold green]SHIP[/]", border_style="green"))
    else:
        body = "\n".join(f"[red]•[/] {escape(r)}" for r in result.reasons)
        console.print(
            Panel(body or "[red]failed[/]", title="[bold red]DON'T SHIP[/]", border_style="red")
        )
    raise typer.Exit(result.exit_code)
