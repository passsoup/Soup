"""Pluggable organisation-signing backends (spec §2, `soup sign --org`).

An organisation signs passports with its *identity* key so a third party sees
"signed by MePlay Corp". Enterprises keep keys in an HSM or existing PKI, so the
signing backend is an interface with swappable implementations:

- ``file``    — an ed25519 private-key PEM on disk (default; works everywhere).
- ``pkcs11``  — a PKCS#11 token / HSM (stub: raises a clear NotImplemented until
                the customer's module is wired — the architecture is here so HSM
                support drops in without touching callers).

All backends implement :class:`Signer`: ``public_key_b64()`` and
``sign(root_hash) -> envelope``. The passport layer only ever talks to this
interface, never to a concrete key type.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol


class Signer(Protocol):
    """A signing backend. The only surface the passport layer depends on."""

    def public_key_b64(self) -> str:  # pragma: no cover - protocol
        ...

    def sign_root_hash(self, root_hash: str) -> dict[str, str]:  # pragma: no cover
        ...


class FileSigner:
    """ed25519 private-key-in-a-PEM-file signer (the default backend)."""

    backend = "file"

    def __init__(self, private_key: Any) -> None:
        self._key = private_key

    @classmethod
    def from_pem(cls, path: str) -> "FileSigner":
        from soup_cli.passport import crypto

        return cls(crypto.load_private_key_pem(path))

    @classmethod
    def generate(cls) -> "FileSigner":
        from soup_cli.passport import crypto

        return cls(crypto.generate_private_key())

    def public_key_b64(self) -> str:
        from soup_cli.passport import crypto

        return crypto.public_key_b64(self._key)

    def sign_root_hash(self, root_hash: str) -> dict[str, str]:
        from soup_cli.passport import crypto

        return crypto.sign_root_hash(self._key, root_hash)


class Pkcs11Signer:
    """HSM / PKCS#11 signer — interface stub for Enterprise integration.

    Wiring a real token requires the customer's PKCS#11 module + slot/PIN config;
    that is deployment-specific and out of scope for the open core. The class
    exists so ``soup sign --org --hsm <config>`` has a home and the rest of the
    code is already backend-agnostic.
    """

    backend = "pkcs11"

    def __init__(self, config: Optional[str] = None) -> None:
        self._config = config

    def _unavailable(self) -> Any:
        raise NotImplementedError(
            "PKCS#11 / HSM signing is an Enterprise integration point. Provide "
            "your module + slot config; the FileSigner backend works offline "
            "today. See docs/passport.md#hsm."
        )

    def public_key_b64(self) -> str:
        return self._unavailable()

    def sign_root_hash(self, root_hash: str) -> dict[str, str]:
        return self._unavailable()


def get_signer(
    backend: str, *, key_path: Optional[str] = None, hsm: Optional[str] = None
) -> Signer:
    """Resolve a signing backend by name.

    ``file`` (default) needs ``key_path``; ``pkcs11`` needs ``hsm`` config.
    """
    backend = (backend or "file").lower()
    if backend == "file":
        if not key_path:
            raise ValueError("file signer requires --key <private.pem>")
        return FileSigner.from_pem(key_path)
    if backend in ("pkcs11", "hsm"):
        return Pkcs11Signer(hsm)
    raise ValueError(f"unknown signing backend {backend!r} (file | pkcs11)")
