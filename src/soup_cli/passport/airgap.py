"""Air-gap bundle builder (spec §6, `soup airgap`).

Produce a single portable artifact from which the whole Soup Passport pipeline
runs on a machine with **zero** internet: the CLI (optionally vendored as wheels),
an offline docs copy, a seed passport registry, an optional license file and base
models, plus a ``run_pipeline.sh`` that exercises
``scan → eval → gate → passport → verify`` offline.

Only the *build* step may touch the network (to vendor wheels); the resulting
bundle is fully offline, which the acceptance test (``tests/e2e_airgap.sh`` /
``tests/passport/test_airgap.py``) verifies by running the pipeline with no
network access.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Optional

from soup_cli.passport.environ import utc_now_iso
from soup_cli.passport.hashing import hash_file

BUNDLE_VERSION = "1.0"

# The offline demo the bundle ships. Pure pipeline, no network. Uses a tiny
# fake safetensors checkpoint and replay-mode eval so it runs anywhere.
_RUN_PIPELINE_SH = r"""#!/usr/bin/env bash
# Offline acceptance run: scan -> eval -> gate -> passport -> verify.
# Requires only `soup` on PATH (install from ./wheels if present). No network.
set -euo pipefail
cd "$(dirname "$0")"

if [ -d wheels ] && ! command -v soup >/dev/null 2>&1; then
  pip install --no-index --find-links wheels soup-cli[sign] >/dev/null
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -r demo/* "$WORK"/
cd "$WORK"

echo "== scan =="      && soup scan  --model ckpt
echo "== eval =="      && soup passport eval --suite smoke --predictions preds.jsonl
echo "== gate =="      && soup gate  --min-score arithmetic=0.8 --require-clean-scan
echo "== train rec ==" && soup passport train --base ./ckpt --method lora --out ./ckpt
echo "== passport ==" && soup passport build --name airgap-demo --version 1.0.0 --out passport.json
echo "== verify =="    && soup verify passport.json
echo "AIR-GAP PIPELINE OK"
"""

_README_TXT = """Soup Passport — Air-gap bundle
================================

This bundle runs the whole Soup Passport pipeline with NO internet.

1. (Optional) install the vendored CLI:
     pip install --no-index --find-links wheels 'soup-cli[sign]'
   or use an already-installed `soup`.

2. Run the offline acceptance pipeline:
     ./run_pipeline.sh
   It performs scan -> eval -> gate -> passport -> verify and prints
   "AIR-GAP PIPELINE OK" on success — with zero network calls.

3. Verify passports offline anytime:
     soup verify <passport.json>
   or open web/verify/index.html in a browser (client-side, no server).

Contents:
  wheels/        vendored Python wheels (if built with --include-wheels)
  docs/          offline documentation
  web/verify/    client-side passport verifier (static HTML)
  demo/          a tiny checkpoint + evidence to run the pipeline
  registry/      seed passport registry (passports only — no weights/data)
  license.key    offline license file (if provided at build)
  manifest.json  bundle manifest + checksums
"""


def _write_demo(demo_dir: Path) -> None:
    """Create a minimal, self-contained pipeline demo (fake checkpoint + preds)."""
    ckpt = demo_dir / "ckpt"
    ckpt.mkdir(parents=True, exist_ok=True)
    (ckpt / "model.safetensors").write_bytes(b"airgap-demo-weights")
    (ckpt / "config.json").write_text('{"arch": "demo"}', encoding="utf-8")
    preds = [
        {"prediction": "OK"},
        {"prediction": "ready"},
        {"prediction": "4"},
        {"prediction": "7"},
        {"prediction": "Paris"},
        {"prediction": "Mars"},
    ]
    (demo_dir / "preds.jsonl").write_text(
        "\n".join(json.dumps(r) for r in preds) + "\n", encoding="utf-8"
    )


def _vendor_wheels(wheels_dir: Path) -> bool:
    """Best-effort: download soup-cli wheels for offline install. Network at build."""
    wheels_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["pip", "wheel", "soup-cli[sign]", "-w", str(wheels_dir)],
            check=True,
            capture_output=True,
            timeout=600,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def build_bundle(
    out_path: str,
    *,
    include_wheels: bool = False,
    license_file: Optional[str] = None,
    include_models: Optional[list[str]] = None,
    docs_dir: Optional[str] = None,
    web_verify_dir: Optional[str] = None,
    registry_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble the air-gap bundle tarball; return its manifest."""
    staging = Path(tempfile.mkdtemp(prefix="soup-airgap-"))
    try:
        (staging / "README.txt").write_text(_README_TXT, encoding="utf-8")
        run_sh = staging / "run_pipeline.sh"
        run_sh.write_text(_RUN_PIPELINE_SH, encoding="utf-8")
        os.chmod(run_sh, 0o755)

        _write_demo(staging / "demo")

        manifest: dict[str, Any] = {
            "bundle_version": BUNDLE_VERSION,
            "created_at": utc_now_iso(),
            "contents": ["README.txt", "run_pipeline.sh", "demo/"],
            "wheels_included": False,
            "models_included": [],
        }

        if include_wheels:
            ok = _vendor_wheels(staging / "wheels")
            manifest["wheels_included"] = ok
            if ok:
                manifest["contents"].append("wheels/")

        # Offline docs.
        docs_src = Path(docs_dir) if docs_dir else Path("docs")
        if docs_src.is_dir():
            shutil.copytree(docs_src, staging / "docs", dirs_exist_ok=True)
            manifest["contents"].append("docs/")

        # Client-side verifier.
        web_src = Path(web_verify_dir) if web_verify_dir else Path("web/verify")
        if web_src.is_dir():
            shutil.copytree(web_src, staging / "web" / "verify", dirs_exist_ok=True)
            manifest["contents"].append("web/verify/")

        # Seed registry (passports only).
        if registry_dir and Path(registry_dir).is_dir():
            shutil.copytree(registry_dir, staging / "registry", dirs_exist_ok=True)
            manifest["contents"].append("registry/")

        # Offline license.
        if license_file and Path(license_file).is_file():
            shutil.copy2(license_file, staging / "license.key")
            manifest["contents"].append("license.key")

        # Optional base models.
        for m in include_models or []:
            mp = Path(m)
            if mp.exists():
                dest = staging / "models" / mp.name
                if mp.is_dir():
                    shutil.copytree(mp, dest, dirs_exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(mp, dest)
                manifest["models_included"].append(mp.name)
        if manifest["models_included"]:
            manifest["contents"].append("models/")

        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )

        # Tar it (gzip for portability; zstd is not guaranteed on the target).
        with tarfile.open(out_path, "w:gz") as tar:
            for item in sorted(staging.iterdir()):
                tar.add(item, arcname=item.name)

        manifest["bundle_path"] = out_path
        manifest["bundle_sha256"] = hash_file(out_path)
        return manifest
    finally:
        shutil.rmtree(staging, ignore_errors=True)
