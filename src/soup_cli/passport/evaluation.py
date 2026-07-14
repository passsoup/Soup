"""Eval suites + regression checks (spec `soup passport eval`, block 4).

The passport's evaluation block answers two questions a buyer actually asks:
*"is it good enough at the target task?"* and *"did fine-tuning break something
it used to do?"* (catastrophic forgetting). So an eval produces, per task, a
score plus — when a baseline is supplied — a **delta** and a **regression** flag.

Two ways to get model outputs, so the whole pipeline runs offline *and* torch-free
in CI while real users get real generations:

- **replay mode** (``--predictions preds.jsonl``): you already have the model's
  answers; we just score them. This is what the offline acceptance test uses.
- **live mode**: if ``transformers`` is installed we load the checkpoint and
  generate greedily. Absent torch, we ask for ``--predictions`` with a clear
  message rather than pretending.

A *suite* is a list of tasks; a task is a list of items ``{prompt, expected,
metric}``. Metrics are simple, transparent string checks (exact / contains /
normalised) — no hidden judge model, because the score has to be reproducible by
anyone verifying the passport.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
_WS = re.compile(r"\s+")


def _normalise(s: str) -> str:
    return _WS.sub(" ", str(s).strip().lower())


def metric_exact(pred: str, expected: str) -> float:
    return 1.0 if str(pred).strip() == str(expected).strip() else 0.0


def metric_normalised(pred: str, expected: str) -> float:
    return 1.0 if _normalise(pred) == _normalise(expected) else 0.0


def metric_contains(pred: str, expected: str) -> float:
    return 1.0 if _normalise(expected) in _normalise(pred) else 0.0


_METRICS: dict[str, Callable[[str, str], float]] = {
    "exact": metric_exact,
    "normalised": metric_normalised,
    "normalized": metric_normalised,
    "contains": metric_contains,
}


# --------------------------------------------------------------------------- #
# Suite model
# --------------------------------------------------------------------------- #
@dataclass
class EvalItem:
    prompt: str
    expected: str
    metric: str = "contains"
    task: str = "default"


@dataclass
class Suite:
    name: str
    items: list[EvalItem] = field(default_factory=list)

    def tasks(self) -> list[str]:
        return sorted({it.task for it in self.items})

    def prompts(self) -> list[str]:
        return [it.prompt for it in self.items]


# A tiny built-in suite so `eval` works out of the box with zero setup. These
# are format/instruction-following checks — deterministic and model-agnostic.
_BUILTIN_SMOKE = [
    {"task": "format", "prompt": "Reply with exactly: OK", "expected": "OK"},
    {"task": "format", "prompt": "Return the word 'ready' lowercase.", "expected": "ready"},
    {"task": "arithmetic", "prompt": "What is 2+2? Answer with the number.", "expected": "4"},
    {"task": "arithmetic", "prompt": "What is 10 minus 3?", "expected": "7"},
    {"task": "knowledge", "prompt": "What is the capital of France?", "expected": "Paris"},
    {"task": "knowledge", "prompt": "Which planet is the Red Planet?", "expected": "Mars"},
]


def builtin_suite(name: str = "smoke") -> Suite:
    if name != "smoke":
        raise ValueError(f"unknown built-in suite {name!r} (only 'smoke' is built in)")
    return Suite(
        name="smoke",
        items=[
            EvalItem(prompt=d["prompt"], expected=d["expected"], metric="contains", task=d["task"])
            for d in _BUILTIN_SMOKE
        ],
    )


def load_suite(name_or_path: str) -> Suite:
    """Load a suite: the built-in name ``smoke``, or a path to a JSONL/JSON file.

    JSONL rows are ``{"prompt", "expected", "metric"?, "task"?}``.
    """
    p = Path(name_or_path)
    if not p.exists():
        return builtin_suite(name_or_path)
    items: list[EvalItem] = []
    text = p.read_text(encoding="utf-8")
    rows: list[dict]
    if p.suffix.lower() == ".json":
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("items", [])
    else:  # jsonl
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    for row in rows:
        if not isinstance(row, dict) or "prompt" not in row or "expected" not in row:
            continue
        items.append(
            EvalItem(
                prompt=str(row["prompt"]),
                expected=str(row["expected"]),
                metric=str(row.get("metric", "contains")),
                task=str(row.get("task", "default")),
            )
        )
    if not items:
        raise ValueError(f"suite {name_or_path!r} contained no usable items")
    return Suite(name=p.stem, items=items)


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def _load_predictions(path: str) -> list[str]:
    """Load predictions from a JSONL (one row per prompt).

    Accepts ``{"prediction": ...}`` / ``{"output": ...}`` / ``{"response": ...}``
    or a bare string per line.
    """
    p = Path(path)
    preds: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            preds.append(line)
            continue
        if isinstance(row, str):
            preds.append(row)
        elif isinstance(row, dict):
            preds.append(
                str(row.get("prediction") or row.get("output") or row.get("response") or "")
            )
        else:
            preds.append(str(row))
    return preds


def score_suite(suite: Suite, predictions: list[str]) -> dict[str, dict[str, Any]]:
    """Score predictions against the suite; return per-task ``{score, n, correct}``.

    ``predictions`` is aligned positionally with ``suite.items``.
    """
    if len(predictions) != len(suite.items):
        raise ValueError(
            f"prediction count {len(predictions)} != item count {len(suite.items)}"
        )
    per_task: dict[str, list[float]] = {}
    for item, pred in zip(suite.items, predictions):
        metric = _METRICS.get(item.metric, metric_contains)
        per_task.setdefault(item.task, []).append(metric(pred, item.expected))
    scores: dict[str, dict[str, Any]] = {}
    for task, vals in per_task.items():
        scores[task] = {
            "score": round(sum(vals) / len(vals), 4),
            "n": len(vals),
            "correct": int(sum(vals)),
        }
    return scores


# --------------------------------------------------------------------------- #
# Live generation (optional; needs transformers)
# --------------------------------------------------------------------------- #
def generation_available() -> bool:
    try:
        import transformers  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def generate_predictions(
    model_path: str, prompts: list[str], *, max_new_tokens: int = 32
) -> list[str]:
    """Greedily generate one completion per prompt using a local checkpoint.

    Live mode. Raises ``RuntimeError`` (with the fix) when transformers is
    absent, so callers can fall back to ``--predictions``.
    """
    if not generation_available():
        raise RuntimeError(
            "live evaluation needs the training stack. Either install "
            "'soup-cli[train]' or pass --predictions <preds.jsonl> (replay mode)."
        )
    from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore

    tok = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(model_path)
    model.eval()
    preds: list[str] = []
    for prompt in prompts:
        inputs = tok(prompt, return_tensors="pt")
        out = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        text = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        preds.append(text)
    return preds


# --------------------------------------------------------------------------- #
# Top-level eval + regression
# --------------------------------------------------------------------------- #
@dataclass
class EvalResult:
    suite: str
    scores: dict[str, dict[str, Any]]
    regression_threshold: float = 0.0
    baseline_source: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "suite": self.suite,
            "scores": self.scores,
            "regression_threshold": self.regression_threshold,
            "baseline_source": self.baseline_source,
            "regressions": [t for t, s in self.scores.items() if s.get("regression")],
        }

    @property
    def has_regressions(self) -> bool:
        return any(s.get("regression") for s in self.scores.values())


def _baseline_scores_from(baseline: Optional[str]) -> dict[str, float]:
    """Extract per-task 'after' scores from a baseline passport or eval.json."""
    if not baseline:
        return {}
    p = Path(baseline)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    # A passport: blocks.evaluation.scores has {task: {after: ...}}.
    ev = data.get("blocks", {}).get("evaluation") if isinstance(data, dict) else None
    if ev and isinstance(ev.get("scores"), dict):
        return {
            t: float(v.get("after", v.get("score", 0.0)))
            for t, v in ev["scores"].items()
            if isinstance(v, dict)
        }
    # An eval.json: {scores: {task: {score|after}}}.
    scores = data.get("scores") if isinstance(data, dict) else None
    if isinstance(scores, dict):
        return {
            t: float(v.get("after", v.get("score", 0.0)))
            for t, v in scores.items()
            if isinstance(v, dict)
        }
    return {}


def evaluate(
    suite: Suite,
    predictions: list[str],
    *,
    baseline: Optional[str] = None,
    regression_threshold: float = 0.0,
) -> EvalResult:
    """Score predictions and, against a baseline, compute deltas + regressions.

    A task regresses when ``after - before < -regression_threshold`` (default
    threshold 0.0 → any drop counts).
    """
    raw = score_suite(suite, predictions)
    baseline_scores = _baseline_scores_from(baseline)
    scores: dict[str, dict[str, Any]] = {}
    for task, entry in raw.items():
        after = float(entry["score"])
        before = baseline_scores.get(task)
        record: dict[str, Any] = {
            "after": after,
            "n": entry["n"],
            "correct": entry["correct"],
        }
        if before is not None:
            delta = round(after - before, 4)
            record["before"] = before
            record["delta"] = delta
            record["regression"] = delta < -abs(regression_threshold)
        else:
            record["before"] = None
            record["delta"] = None
            record["regression"] = False
        scores[task] = record
    return EvalResult(
        suite=suite.name,
        scores=scores,
        regression_threshold=regression_threshold,
        baseline_source=baseline,
    )


def resolve_predictions(
    *, model: Optional[str], predictions: Optional[str], suite: Suite, max_new_tokens: int = 32
) -> list[str]:
    """Get predictions from a file (replay) or by generating (live)."""
    if predictions:
        preds = _load_predictions(predictions)
        if len(preds) != len(suite.items):
            raise ValueError(
                f"--predictions has {len(preds)} rows but the suite has "
                f"{len(suite.items)} items"
            )
        return preds
    if model:
        return generate_predictions(model, suite.prompts(), max_new_tokens=max_new_tokens)
    raise ValueError("provide either --model (live) or --predictions (replay)")
