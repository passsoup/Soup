# Soup Model Passport

> **Soup gives every model a passport.** Fine-tune, evaluate, scan, and *prove* —
> all on hardware you control. The product of every run is a cryptographically
> signed **Model Passport** that a regulator, auditor, or enterprise buyer can
> verify **without ever touching your weights or your data**.

Positioning: **"Vanta for models."** Training is the free entry; provable trust
is the business. Everything below runs at **zero internet** — the only command
that legitimately uses the network is the passport registry (`push`/`pull`/`serve`).

We sell the printer, never the paper: **the documents stay with you.**

---

## The 60-second tour

```bash
pip install 'soup-cli[sign]'          # the passport needs the crypto extra

# Free core — the offline pipeline (no GPU, no network needed to try it):
soup scan  --model ./output                                   # integrity + backdoor scan
soup passport eval --model ./output --suite smoke             # eval + regression check
soup gate  --min-score arithmetic=0.8 --require-clean-scan    # SHIP / DON'T SHIP (exit 4 fails CI)
soup passport train --base ./base --method lora --out ./output  # record training evidence
soup passport build --name my-llm --version 1.0.0 --out passport.json   # assemble + self-sign
soup verify passport.json                                     # ✔ VALID / ✘ INVALID
```

Then the viral part: send `passport.json` to anyone. They verify it with
`soup verify`, or by dropping it into **[passsoup.dev/verify](https://passsoup.dev/verify)**
(or the local `web/verify/index.html`) — a read-only page that checks the
signature **in their browser**, so the passport never leaves their machine.

---

## What's in a passport

One canonical, signed JSON file with **seven blocks** — only hashes and evidence,
never raw data or weights:

| # | Block | Captured by |
|---|---|---|
| 1 | **Identity** — base model + hash, license, derivative obligations | `passport train` |
| 2 | **Data provenance** — dataset fingerprints, PII scan, origin legality | `passport train` |
| 3 | **Training record** — method, hyperparameters, hardware, duration, environment | `passport train` |
| 4 | **Evaluation** — before/after scores, regressions, gate verdict | `passport eval` + `gate` |
| 5 | **Security** — artifact integrity, backdoor scan | `scan` |
| 6 | **Accountability** — who ran it, when, the cryptographic signature | `passport build` / `sign` |
| 7 | **Lineage** — version history, diff from a parent passport | `passport build --parent` |

Anything that cannot be substantiated is left at its `unattested` default **and**
listed in `unattested_fields`. We never invent evidence — that honesty is a
feature, printed on the passport itself.

### Provenance class

- **`native`** — recorded inside Soup at training time (a birth certificate).
- **`attested`** — produced by `soup adopt` for a model trained elsewhere; only
  what can be re-checked after the fact is attested, the rest is `unattested`.

### How verification works (identical in CLI and browser)

1. Every block is canonicalised (`sorted keys, no whitespace, JS-compatible
   number formatting`) and hashed: `block_hashes[b] = sha256(canonical(block))`.
2. `root_hash = sha256(canonical(block_hashes))`.
3. The `root_hash` is signed with **Ed25519**. Flip any byte in any block and the
   block hash changes → `root_hash` changes → the signature no longer verifies.

`soup verify` and the `/verify` web page run this exact algorithm. We follow the
OpenSSF Model Signing / Sigstore direction (detached signature + public key in
the envelope) rather than inventing a proprietary format.

---

## Command reference

### Free, forever

| Command | Purpose |
|---|---|
| `soup scan --model <ckpt> [--deep]` | Checkpoint integrity + backdoor/tamper scan. Exit 4 on a threat. |
| `soup passport eval --suite <name\|path> [--model \| --predictions]` | Eval suite + regression deltas vs a baseline passport. |
| `soup gate [--min-score t=0.8] [--no-regressions] [--require-clean-scan]` | SHIP / DON'T SHIP. Exit 0 / 4 for CI. |
| `soup passport train --base <m> --method <lora\|qlora\|full> [--data ...]` | Record training evidence (fingerprints only). |
| `soup passport build --name <n> --version <v>` | Assemble + self-sign the passport (Ed25519). |
| `soup passport show <passport.json> [--md]` | Human-readable view of the seven blocks. |
| `soup verify <passport.json> [--key <b64>]` | Verify signature + hash chain. Exit 0 / 4. **Free for the whole world.** |
| `soup pack render --pack model-card ...` | Render the free model-card document. |
| `soup license activate/status/deactivate` | Manage the offline license. |

### Paid (require an active license — see below)

| Command | Tier | Purpose |
|---|---|---|
| `soup sign <passport> --org "MePlay Corp"` | Pro | Re-sign with an organisation identity key. |
| `soup pack render --pack <name> ...` | Pro / Ent | Regulator/buyer document packs (below). |
| `soup adopt <ckpt>` | Paid / model | BYOM: deep-scan + eval an external model → Attested passport. |
| `soup passport push/pull/list --url ...` | Pro | Passport registry client (hosted). |
| `soup passport serve --data-dir ...` | Ent | Self-hosted passport registry (stores only passports). |
| `soup airgap build` | Ent | Single portable offline bundle for the whole pipeline. |

Exit codes (for CI): `0` ok/SHIP/VALID/CLEAN · `1` error · `2` bad args ·
`3` license required · `4` check failed (DON'T SHIP / INVALID / threat).

---

## Export packs — one passport, many documents

`soup pack render --pack <name> --passport passport.json --out doc.md` maps the
passport onto the sections a given regulator or buyer expects. A new regulation
is a new renderer, never a new product. All packs are **audit-ready** evidence —
never "compliant", never a claim of regulator recognition.

| Pack | Tier | Document |
|---|---|---|
| `model-card` | Free | Industry-standard model card. |
| `eu-ai-act-gpai` | Pro | EU AI Act GPAI provider docs + public training-data summary. |
| `gdpr` | Pro | DPIA skeleton + Art. 30 processing record. |
| `bank-mrm` | Ent | US bank Model Risk package (SR 26-2 principles). |
| `eu-ai-act-highrisk` | Ent | Annex IV technical documentation. |
| `hipaa` | Ent | De-identification evidence package. |
| `nist-ai-rmf` / `iso-42001` | Ent | Voluntary-framework mappings. |

`soup pack list` shows the full table with tiers.

---

## Licensing (offline, JetBrains-style)

Paid features activate from a **signed license file** — no server, no phone-home,
so it works in an air-gapped datacenter:

```bash
soup license activate meplay.license.key    # verified against a baked-in issuer key
soup license status                        # tier, expiry, permitted features
```

A paid command calls `licensing.require(<feature>)` at its first line; without a
covering license it prints a clear message and exits `3`. See
[`tools/issue_license.py`](../tools/issue_license.py) for minting licenses (the
seller side; the issuer private key never ships in the repo).

<a id="hsm"></a>
### Enterprise signing (HSM / PKCS#11)

`soup sign --org` uses a pluggable signing backend. `--backend file` (default)
signs with an Ed25519 PEM. `--backend pkcs11 --hsm <config>` is the integration
point for a hardware token / existing PKI; wire your module and the rest of the
pipeline is already backend-agnostic (`soup_cli.passport.signers`).

---

## Passport registry

Stores **only passports (hashes)** — never weights or data.

```bash
# Enterprise self-hosted server (on your infrastructure):
soup passport serve --host 0.0.0.0 --port 8721 --data-dir ./registry --token <org-key>

# Pro client:
soup passport push  passport.json --url https://reg.meplay.com --token <org-key>
soup passport list  --url https://reg.meplay.com --token <org-key>
soup passport pull  <id> --url https://reg.meplay.com --out fetched.json
```

Endpoints: `POST /passports`, `GET /passports`, `GET /passports/{id}`,
`GET /verify/{id}` (reuses the shared verification core). Bearer-token auth gates
publishing; passports are public-verifiable by design.

---

## Air-gap bundle

```bash
soup airgap build --out soup-airgap.tar.gz --include-wheels --license meplay.license.key
```

Produces a single tarball that runs the whole pipeline on an isolated machine:
CLI wheels (optional), offline docs, the client-side verifier, a demo checkpoint
+ evidence, a seed registry, and a `run_pipeline.sh` that executes
`scan → eval → gate → passport → verify` with **zero network**. The acceptance
test is [`tests/e2e_airgap.sh`](../tests/e2e_airgap.sh).

---

## The /verify web page

`web/verify/index.html` is a single, self-contained, dependency-free page. It
verifies a passport **entirely in the browser** (pure-JS Ed25519 + SHA-256, the
same canonical form as the CLI), so the passport never leaves the auditor's
device. Open it directly or serve it:

```bash
python -m http.server -d web/verify 8000   # then open http://localhost:8000
```

Green on a valid passport; red — naming the altered block — on a tampered one.
Every third-party verification recruits the next Soup user; that is why `verify`
and `/verify` are free forever.
