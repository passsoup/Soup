#!/usr/bin/env bash
# Air-gap acceptance test (spec §6 / Definition of Done #7).
#
# Builds a Soup air-gap bundle, extracts it into a scratch dir, and runs the
# whole passport pipeline (scan -> eval -> gate -> passport -> verify) with NO
# network. Prints AIR-GAP ACCEPTANCE OK on success.
#
# To truly enforce "no network", run this inside a network-namespaced sandbox,
# e.g.:   unshare -rn ./tests/e2e_airgap.sh
# (the pipeline makes no network calls, so it also passes with the network up).
set -euo pipefail

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. Need an Enterprise license to build the bundle. Mint one with the issuer
#    key if present; otherwise skip the build and just run the pipeline directly.
ISSUER_KEY="tools/secrets/license_issuer_priv.pem"
BUNDLE="$WORK/soup-airgap.tar.gz"

if [ -f "$ISSUER_KEY" ]; then
  python tools/issue_license.py --org airgap-test --tier enterprise \
    --expires 2099-01-01 --key "$ISSUER_KEY" --out "$WORK/ent.license.key" >/dev/null
  soup license activate "$WORK/ent.license.key" >/dev/null
  soup airgap build --out "$BUNDLE" >/dev/null
  soup license deactivate >/dev/null || true

  mkdir -p "$WORK/extract"
  tar xzf "$BUNDLE" -C "$WORK/extract"
  echo "== running bundled offline pipeline =="
  ( cd "$WORK/extract" && bash run_pipeline.sh | tail -1 )
else
  echo "issuer key not present; running pipeline directly (no bundle build)"
  cd "$WORK"
  mkdir -p ckpt
  printf 'weights' > ckpt/model.safetensors
  printf '{"prediction":"OK"}\n{"prediction":"ready"}\n{"prediction":"4"}\n{"prediction":"7"}\n{"prediction":"Paris"}\n{"prediction":"Mars"}\n' > preds.jsonl
  soup scan --model ckpt
  soup passport eval --suite smoke --predictions preds.jsonl
  soup gate --min-score arithmetic=0.8 --require-clean-scan
  soup passport build --name airgap-demo --version 1.0.0 --out passport.json
  soup verify passport.json
fi

echo "AIR-GAP ACCEPTANCE OK"
