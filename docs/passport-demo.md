# Soup Model Passport — Definition of Done & the 2-minute sales demo

## Definition of Done — verified

| # | Requirement | Status |
|---|---|---|
| 1 | `pip install .` installs `soup` as an executable command | ✅ (`soup version`) |
| 2 | Full offline pipeline `scan → eval → gate → passport → verify` runs with **zero network** on a tiny model | ✅ all exit 0 |
| 3 | `soup verify` is green on a valid passport, red on a tampered one (any byte) | ✅ valid → exit 0, tampered → exit 4 |
| 4 | Paid commands blocked without a license (exit 3), work with a valid offline license | ✅ `sign`/paid packs/`adopt`/`registry`/`airgap` |
| 5 | Offline license activation from a signed file (JetBrains-style, baked-in public key) | ✅ `soup license activate` |
| 6 | `pack model-card` (free) and a paid pack (`eu-ai-act-gpai`) render human-readable docs | ✅ + 6 more packs |
| 7 | `soup airgap build` produces a bundle whose pipeline runs on an isolated machine | ✅ `run_pipeline.sh` → AIR-GAP OK |
| 8 | `/verify` web page validates a passport client-side (green/red) | ✅ verified in Chromium + Node |
| 9 | All tests green; `README.md` + `soup --help` per command | ✅ 71 passport tests, docs/passport.md |
| 10 | No forbidden wording ("compliant"/"compliance guarantee" as a claim) | ✅ only disclaimers/negations |

## The security property that makes it worth money

The signature covers **everything that matters**: all seven blocks *and* the
top-level metadata (model name, version, provenance class, the honest
`unattested` list), folded into one Ed25519 signature over the hash-chain root.
Change a single byte anywhere — a score, a model name, a provenance downgrade —
and `soup verify` (and the browser) turn red and name what changed. Honesty is
enforced by math, not by trust.

---

## The 2-minute sales demo (show these three things)

Setup once (any folder, no GPU, no network):

```bash
pip install 'soup-cli[sign]'
mkdir ckpt && printf 'weights' > ckpt/model.safetensors
printf '{"prediction":"OK"}\n{"prediction":"ready"}\n{"prediction":"4"}\n{"prediction":"7"}\n{"prediction":"Paris"}\n{"prediction":"Mars"}\n' > preds.jsonl
soup scan --model ckpt
soup passport eval --suite smoke --predictions preds.jsonl
soup gate --min-score arithmetic=0.8 --require-clean-scan
soup passport build --name meplay-support-llm --version 1.3.0 --out passport.json
```

**1. "Here's the passport."** — a beautiful, signed, seven-block record.

```bash
soup passport show passport.json
```

**2. "Anyone can verify it — green."**

```bash
soup verify passport.json          # ✔ VALID
```

**3. "Now I tamper with one byte — red."**

```bash
python -c "import json;p=json.load(open('passport.json'));p['blocks']['evaluation']['scores']['arithmetic']['after']=0.1;json.dump(p,open('passport.json','w'))"
soup verify passport.json          # ✘ INVALID — 'block evaluation was altered'
```

**The closer:** open `web/verify/index.html` (or **passsoup.dev/verify**) in a
browser and drop the passport in — the same green/red result, computed **in the
buyer's browser**, nothing uploaded. "Your auditor verifies your model without
ever touching your weights or your data. You keep the printer; they get the proof."

### Then, for the enterprise buyer

```bash
soup license activate meplay.license.key        # offline, air-gapped
soup pack render --pack eu-ai-act-gpai --passport passport.json --out gpai.md
soup pack render --pack bank-mrm       --passport passport.json --out mrm.md
soup sign passport.json --org "MePlay Corp"     # verifier now shows "signed by MePlay Corp"
soup airgap build --out soup-airgap.tar.gz    # the whole thing, offline, in one file
```

One passport → EU AI Act, GDPR, bank MRM, HIPAA, NIST/ISO documents. New
regulation = new renderer, never a new product.
