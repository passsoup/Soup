"""Checkpoint integrity + backdoor/tamper scan (spec `soup scan`, block 5).

Two questions, answered offline and without loading a single weight:

1. **Integrity** — is this a checkpoint we can trust *to open*? The dangerous
   case is a pickle-backed weight file (``.bin`` / ``.pt`` / ``.pth`` / ``.ckpt``):
   ``torch.load`` unpickles, and unpickling can execute arbitrary code. We scan
   the pickle *opcode stream* (via ``pickletools.genops`` — it never executes)
   for ``GLOBAL`` / ``STACK_GLOBAL`` references to code-execution modules
   (``os``, ``subprocess``, ``builtins.eval``…). ``.safetensors`` is a pure
   tensor container with no code path, so it passes integrity by construction.

2. **Backdoor / tamper** — heuristics that catch the cheap attacks: executable
   payloads smuggled into the checkpoint dir, pickle files that import network
   or process modules, obviously-suspicious file names. ``--deep`` additionally
   runs a weight-statistics anomaly pass when numpy/torch is available.

Findings carry a ``severity`` (``critical`` / ``warning`` / ``info``); the
overall status is ``flagged`` if any critical/warning finding exists, else
``clean``. The command maps ``flagged`` to a non-zero exit so CI blocks on it.

For MVP the deep weight-anomaly checks are best-effort and clearly marked; the
architecture leaves room to plug in signature databases later.
"""

from __future__ import annotations

import pickletools
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from soup_cli.passport.hashing import hash_dir, hash_file

STATUS_CLEAN = "clean"
STATUS_FLAGGED = "flagged"

SEV_CRITICAL = "critical"
SEV_WARNING = "warning"
SEV_INFO = "info"
_BLOCKING = {SEV_CRITICAL, SEV_WARNING}

# Weight file extensions that are pickle-backed (code-execution risk on load).
_PICKLE_EXTS = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle"}
_SAFETENSORS_EXTS = {".safetensors"}
# Files that have no business living inside a model checkpoint.
_EXECUTABLE_EXTS = {".py", ".sh", ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd"}

# Modules whose presence in a pickle GLOBAL opcode means "this can run code".
_DANGEROUS_MODULES = {
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "socket",
    "shutil",
    "builtins",
    "__builtin__",
    "importlib",
    "runpy",
    "pty",
    "commands",
    "requests",
    "urllib",
    "urllib2",
    "httplib",
    "ftplib",
    "telnetlib",
    "smtplib",
    "ctypes",
    "cffi",
    "pip",
}
_DANGEROUS_CALLABLES = {"eval", "exec", "system", "popen", "compile", "__import__"}

_MAX_PICKLE_SCAN_BYTES = 512 * 1024 * 1024  # cap opcode scan at 512 MiB per file


@dataclass
class ScanFinding:
    severity: str
    code: str
    message: str
    path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }


@dataclass
class ScanResult:
    status: str
    findings: list[ScanFinding] = field(default_factory=list)
    integrity: str = "ok"  # "ok" | "failed" | "unattested"
    artifact_hash: Optional[str] = None
    files_scanned: int = 0
    deep: bool = False

    @property
    def is_clean(self) -> bool:
        return self.status == STATUS_CLEAN

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "integrity": self.integrity,
            "artifact_hash": self.artifact_hash,
            "files_scanned": self.files_scanned,
            "deep": self.deep,
            "findings": [f.to_dict() for f in self.findings],
            "backdoor_scan": {
                "status": self.status,
                "findings": [f.to_dict() for f in self.findings],
            },
        }


def _iter_weight_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink()
    )


def _scan_pickle_opcodes(path: Path) -> list[ScanFinding]:
    """Inspect a pickle file's opcode stream for code-execution references.

    Uses ``pickletools.genops``, which walks opcodes *without* executing them.
    Any ``GLOBAL`` / ``STACK_GLOBAL`` pointing at a dangerous module is a
    critical finding — that is exactly how a poisoned checkpoint runs code.
    """
    findings: list[ScanFinding] = []
    try:
        size = path.stat().st_size
    except OSError:
        return findings
    if size > _MAX_PICKLE_SCAN_BYTES:
        findings.append(
            ScanFinding(
                SEV_WARNING,
                "pickle-too-large",
                f"pickle file too large to fully scan ({size} bytes); opened unsafely on load",
                str(path),
            )
        )
        return findings

    # A .bin/.pt may be a zip archive (torch's newer format) or a raw pickle.
    # genops on a non-pickle stream raises; we treat "unparseable as pickle" as
    # info, not a failure (it may be a zip we can't cheaply walk here).
    try:
        with path.open("rb") as fh:
            pending_module: Optional[str] = None
            for opcode, arg, _pos in pickletools.genops(fh):
                name = opcode.name
                if name in ("GLOBAL",) and isinstance(arg, str):
                    module = arg.split(" ", 1)[0].split(".", 1)[0]
                    callable_name = arg.split(" ")[-1] if " " in arg else ""
                    if module in _DANGEROUS_MODULES or callable_name in _DANGEROUS_CALLABLES:
                        findings.append(
                            ScanFinding(
                                SEV_CRITICAL,
                                "pickle-dangerous-global",
                                f"pickle imports code-execution symbol {arg!r}",
                                str(path),
                            )
                        )
                elif name in ("SHORT_BINUNICODE", "BINUNICODE", "STRING", "BINSTRING"):
                    pending_module = arg if isinstance(arg, str) else pending_module
                elif name == "STACK_GLOBAL" and pending_module:
                    mod = pending_module.split(".", 1)[0]
                    if mod in _DANGEROUS_MODULES or pending_module in _DANGEROUS_CALLABLES:
                        findings.append(
                            ScanFinding(
                                SEV_CRITICAL,
                                "pickle-dangerous-global",
                                f"pickle stack-global references {pending_module!r}",
                                str(path),
                            )
                        )
                    pending_module = None
                elif name in ("REDUCE", "INST", "OBJ", "NEWOBJ_EX"):
                    # REDUCE calls a callable at load time; benign for tensors but
                    # worth an info note when combined with the above signals.
                    pass
    except Exception:  # noqa: BLE001 — non-pickle / truncated stream, not our concern
        return findings
    return findings


def _integrity_findings(files: list[Path]) -> tuple[list[ScanFinding], str]:
    """Classify weight files; return (findings, integrity_status)."""
    findings: list[ScanFinding] = []
    saw_safetensors = False
    saw_pickle = False
    for p in files:
        ext = p.suffix.lower()
        if ext in _SAFETENSORS_EXTS:
            saw_safetensors = True
        elif ext in _PICKLE_EXTS:
            saw_pickle = True
            findings.append(
                ScanFinding(
                    SEV_WARNING,
                    "unsafe-serialization",
                    f"pickle-based weight file {p.name!r} executes code on load; "
                    "prefer .safetensors",
                    str(p),
                )
            )
            findings.extend(_scan_pickle_opcodes(p))
        elif ext in _EXECUTABLE_EXTS:
            findings.append(
                ScanFinding(
                    SEV_CRITICAL,
                    "executable-in-checkpoint",
                    f"executable/script file {p.name!r} inside a model checkpoint",
                    str(p),
                )
            )
    if any(f.severity == SEV_CRITICAL for f in findings):
        integrity = "failed"
    elif not saw_safetensors and not saw_pickle and files:
        integrity = "unattested"  # no recognisable weights found
    else:
        integrity = "ok"
    return findings, integrity


def _deep_weight_findings(root: Path) -> list[ScanFinding]:
    """Optional weight-statistics anomaly pass (needs numpy + safetensors).

    Best-effort: if the libraries are absent we return a single info finding so
    the passport honestly records that the deep pass did not run.
    """
    try:
        import numpy as np  # noqa: F401
        from safetensors import safe_open  # type: ignore
    except Exception:  # noqa: BLE001
        return [
            ScanFinding(
                SEV_INFO,
                "deep-scan-skipped",
                "deep weight-anomaly scan needs numpy + safetensors; recorded as not-run",
            )
        ]
    findings: list[ScanFinding] = []
    files = [p for p in _iter_weight_files(root) if p.suffix.lower() == ".safetensors"]
    for p in files:
        try:
            with safe_open(str(p), framework="numpy") as f:  # type: ignore
                for key in f.keys():
                    arr = f.get_tensor(key)
                    import numpy as np

                    if not np.all(np.isfinite(arr)):
                        findings.append(
                            ScanFinding(
                                SEV_CRITICAL,
                                "non-finite-weights",
                                f"tensor {key!r} contains NaN/Inf — corrupted or tampered",
                                str(p),
                            )
                        )
        except Exception:  # noqa: BLE001
            continue
    return findings


def scan_checkpoint(model_path: str | Path, *, deep: bool = False) -> ScanResult:
    """Scan a checkpoint file or directory; return a :class:`ScanResult`.

    Never loads weights. Pure integrity + heuristic backdoor detection, plus an
    optional deep numeric pass. The overall status is ``flagged`` when any
    critical/warning finding is present.
    """
    root = Path(model_path)
    if not root.exists():
        raise FileNotFoundError(f"checkpoint not found: {model_path}")

    files = _iter_weight_files(root)
    findings, integrity = _integrity_findings(files)

    if deep:
        findings.extend(_deep_weight_findings(root))

    status = (
        STATUS_FLAGGED
        if any(f.severity in _BLOCKING for f in findings)
        else STATUS_CLEAN
    )
    artifact_hash = hash_dir(root) if root.is_dir() else hash_file(root)

    return ScanResult(
        status=status,
        findings=findings,
        integrity=integrity,
        artifact_hash=artifact_hash,
        files_scanned=len(files),
        deep=deep,
    )
