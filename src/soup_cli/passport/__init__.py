"""Soup Model Passport — the trust layer on top of the training CLI.

*"Soup gives every model a passport."* Fine-tune, evaluate, scan, and prove — all
on hardware the user controls. The product of every run is a cryptographically
signed **Model Passport** that a regulator, auditor, or enterprise buyer can
verify without ever touching the weights or the data.

This package is the local-first, air-gap-by-birth core:

- :mod:`~soup_cli.passport.hashing`   canonical JSON + SHA-256 (single source of truth)
- :mod:`~soup_cli.passport.schema`    the seven-block passport + hash chain
- :mod:`~soup_cli.passport.crypto`    Ed25519 sign / verify over the root hash
- :mod:`~soup_cli.passport.runstore`  the ``.soup/`` evidence directory
- :mod:`~soup_cli.passport.environ`   offline environment capture
- :mod:`~soup_cli.passport.scanning`  checkpoint integrity + backdoor scan
- :mod:`~soup_cli.passport.evaluation` eval suites + regression checks
- :mod:`~soup_cli.passport.gate`      SHIP / DON'T SHIP verdict
- :mod:`~soup_cli.passport.builder`   assemble + self-sign a passport
- :mod:`~soup_cli.passport.licensing` offline license activation + feature gating
- :mod:`~soup_cli.passport.signers`   pluggable org-signing backends
- :mod:`~soup_cli.passport.packs`     one passport -> many regulator documents
- :mod:`~soup_cli.passport.registry`  passport registry client + self-hosted server
- :mod:`~soup_cli.passport.airgap`    single offline bundle builder

Everything runs at zero-internet. The only command that legitimately uses the
network is ``soup passport push/pull/serve`` (the registry).
"""

from __future__ import annotations

PASSPORT_PRODUCT_VERSION = "1.0"
