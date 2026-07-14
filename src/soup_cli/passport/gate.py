"""The ship gate — a binary SHIP / DON'T SHIP verdict for CI (spec `soup gate`).

``gate`` is the command a CI pipeline actually blocks on. It reads the evidence
already written to ``.soup/`` (``eval.json``, optionally ``scan.json``), applies
a small set of rules, and returns:

- ``SHIP`` → exit 0, or
- ``DON'T SHIP`` → exit 4, with a reason per failed rule.

Rules (any combination):

- **min score** per task (``--min-score task=0.8``) — quality floor,
- **no regressions** (``--no-regressions``) — refuse catastrophic forgetting,
- **clean scan** (``--require-clean-scan``) — refuse a flagged checkpoint.

Rules can also come from a YAML file (``--rules gate.yaml``). The verdict and its
reasons are written to ``gate.json`` so the passport records *why* a model was
cleared to ship.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

VERDICT_SHIP = "SHIP"
VERDICT_DONT_SHIP = "DONT_SHIP"


@dataclass
class GateRules:
    min_scores: dict[str, float] = field(default_factory=dict)
    no_regressions: bool = False
    require_clean_scan: bool = False

    def to_dict(self) -> dict:
        return {
            "min_scores": self.min_scores,
            "no_regressions": self.no_regressions,
            "require_clean_scan": self.require_clean_scan,
        }


@dataclass
class GateResult:
    verdict: str
    reasons: list[str] = field(default_factory=list)
    rules: Optional[GateRules] = None

    @property
    def ship(self) -> bool:
        return self.verdict == VERDICT_SHIP

    @property
    def exit_code(self) -> int:
        return 0 if self.ship else 4

    def to_dict(self) -> dict:
        return {
            "gate_verdict": self.verdict,
            "gate_reasons": self.reasons,
            "rules": self.rules.to_dict() if self.rules else None,
        }


def parse_min_score(pairs: list[str]) -> dict[str, float]:
    """Parse ``["task=0.8", "other=0.5"]`` into ``{task: 0.8, other: 0.5}``."""
    out: dict[str, float] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"--min-score expects task=value, got {pair!r}")
        task, _, val = pair.partition("=")
        task = task.strip()
        try:
            out[task] = float(val)
        except ValueError as exc:
            raise ValueError(f"--min-score value for {task!r} is not a number: {val!r}") from exc
    return out


def rules_from_yaml(data: dict) -> GateRules:
    """Build :class:`GateRules` from a parsed YAML/JSON dict."""
    min_scores = {str(k): float(v) for k, v in (data.get("min_scores") or {}).items()}
    return GateRules(
        min_scores=min_scores,
        no_regressions=bool(data.get("no_regressions", False)),
        require_clean_scan=bool(data.get("require_clean_scan", False)),
    )


def evaluate_gate(
    eval_json: Optional[dict],
    scan_json: Optional[dict],
    rules: GateRules,
) -> GateResult:
    """Apply ``rules`` to the evidence and return SHIP / DON'T SHIP.

    Missing evidence that a rule depends on is itself a DON'T SHIP reason — a
    gate cannot pass on evidence it never saw.
    """
    reasons: list[str] = []

    scores = (eval_json or {}).get("scores", {}) if eval_json else {}

    # Rule: minimum score per task.
    for task, floor in rules.min_scores.items():
        entry = scores.get(task)
        if not isinstance(entry, dict):
            reasons.append(f"min-score: no eval score for task {task!r}")
            continue
        after = entry.get("after", entry.get("score"))
        if after is None:
            reasons.append(f"min-score: task {task!r} has no score")
        elif float(after) < floor:
            reasons.append(
                f"min-score: task {task!r} scored {float(after):.4g} < required {floor:.4g}"
            )

    # Rule: no regressions.
    if rules.no_regressions:
        if not eval_json:
            reasons.append("no-regressions: no eval evidence (.soup/eval.json missing)")
        else:
            regressed = [
                t for t, s in scores.items() if isinstance(s, dict) and s.get("regression")
            ]
            for t in regressed:
                delta = scores[t].get("delta")
                reasons.append(
                    f"no-regressions: task {t!r} regressed (delta {delta})"
                )

    # Rule: clean scan required.
    if rules.require_clean_scan:
        if not scan_json:
            reasons.append("require-clean-scan: no scan evidence (.soup/scan.json missing)")
        elif scan_json.get("status") != "clean" or scan_json.get("integrity") == "failed":
            reasons.append(
                f"require-clean-scan: scan status is {scan_json.get('status')!r} "
                f"(integrity {scan_json.get('integrity')!r})"
            )

    verdict = VERDICT_SHIP if not reasons else VERDICT_DONT_SHIP
    return GateResult(verdict=verdict, reasons=reasons, rules=rules)
