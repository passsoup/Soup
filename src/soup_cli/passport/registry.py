"""Passport registry — store, serve, and fetch passports (spec §5).

**Stores only passports (hashes) — never weights or data.** An organisation can
publish its signed passports so auditors and buyers can pull and verify them.

Three pieces, all dependency-light (stdlib ``http.server`` + ``urllib``) so the
registry runs in an air-gapped datacenter with nothing extra installed:

- :class:`PassportStore` — a file-backed store keyed by a content id derived from
  the passport's root hash (content-addressed, so the same passport dedupes).
- :func:`make_server` — a self-hosted HTTP server (``soup passport serve``, Ent)
  exposing ``POST /passports``, ``GET /passports``, ``GET /passports/{id}``,
  ``GET /verify/{id}`` (which reuses the shared crypto core).
- :class:`RegistryClient` — push / pull / list over HTTP(S) (``soup passport
  push/pull/list``). This is the *one* place networking is normal in the product.

Auth is a simple bearer token (the org key). Not a full IAM — the passport is
public-verifiable by design; the token only gates who may *publish*.
"""

from __future__ import annotations

import hashlib
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from soup_cli.passport import crypto

_ID_RE = re.compile(r"^[a-f0-9]{8,64}$")
_MAX_BODY_BYTES = 32 * 1024 * 1024


def passport_id(passport: dict) -> str:
    """Content id for a passport: short SHA-256 of its root hash (stable)."""
    root = passport.get("hash_chain", {}).get("root_hash", "")
    if not root:
        root = json.dumps(passport.get("blocks", {}), sort_keys=True)
    return hashlib.sha256(root.encode("utf-8")).hexdigest()[:16]


class PassportStore:
    """File-backed passport store. One JSON file per passport, plus an index."""

    def __init__(self, data_dir: str | Path = ".soup-registry") -> None:
        self.root = Path(data_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, pid: str) -> Path:
        if not _ID_RE.match(pid):
            raise ValueError(f"invalid passport id {pid!r}")
        return self.root / f"{pid}.json"

    def put(self, passport: dict) -> str:
        pid = passport_id(passport)
        path = self.root / f"{pid}.json"
        path.write_text(json.dumps(passport, indent=2, sort_keys=True), encoding="utf-8")
        return pid

    def get(self, pid: str) -> Optional[dict]:
        path = self._path(pid)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self, *, name_filter: Optional[str] = None) -> list[dict]:
        """Return summaries (id, model, provenance, gate) for stored passports."""
        out: list[dict] = []
        for p in sorted(self.root.glob("*.json")):
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            model = doc.get("model", {})
            name = model.get("name", "")
            if name_filter and name_filter not in str(name):
                continue
            out.append(
                {
                    "id": p.stem,
                    "name": name,
                    "version": model.get("version"),
                    "provenance_class": doc.get("provenance_class"),
                    "gate_verdict": doc.get("blocks", {}).get("evaluation", {}).get("gate_verdict"),
                }
            )
        return out

    def verify(self, pid: str) -> Optional[dict]:
        doc = self.get(pid)
        if doc is None:
            return None
        return crypto.verify_passport(doc).to_dict()


# --------------------------------------------------------------------------- #
# Server (self-hosted, Enterprise)
# --------------------------------------------------------------------------- #
def make_server(
    host: str, port: int, store: PassportStore, *, token: Optional[str] = None
) -> ThreadingHTTPServer:
    """Build (but do not start) an HTTP server exposing the registry API."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "SoupPassportRegistry/1.0"

        def _send(self, code: int, obj: Any) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            if not token:
                return True
            got = self.headers.get("Authorization", "")
            return got == f"Bearer {token}"

        def log_message(self, *args):  # noqa: A002 — silence default stderr logging
            pass

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                return self._send(200, {"status": "ok"})
            m = re.match(r"^/passports/([a-f0-9]{8,64})$", self.path)
            if m:
                doc = store.get(m.group(1))
                return self._send(200, doc) if doc else self._send(404, {"error": "not found"})
            m = re.match(r"^/verify/([a-f0-9]{8,64})$", self.path)
            if m:
                res = store.verify(m.group(1))
                return self._send(200, res) if res else self._send(404, {"error": "not found"})
            if self.path == "/passports" or self.path.startswith("/passports?"):
                return self._send(200, {"passports": store.list()})
            return self._send(404, {"error": "unknown route"})

        def do_POST(self):  # noqa: N802
            if self.path != "/passports":
                return self._send(404, {"error": "unknown route"})
            if not self._authed():
                return self._send(401, {"error": "unauthorized (bad or missing token)"})
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > _MAX_BODY_BYTES:
                return self._send(400, {"error": "bad content length"})
            try:
                doc = json.loads(self.rfile.read(length))
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "invalid JSON"})
            if not isinstance(doc, dict) or "hash_chain" not in doc:
                return self._send(400, {"error": "not a passport"})
            pid = store.put(doc)
            return self._send(201, {"id": pid})

    return ThreadingHTTPServer((host, port), Handler)


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
class RegistryClient:
    """HTTP(S) client for push / pull / list. Uses urllib (stdlib)."""

    def __init__(
        self, base_url: str, *, token: Optional[str] = None, timeout: float = 15.0
    ) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, *, body: Optional[dict] = None) -> Any:
        import urllib.error
        import urllib.request

        url = f"{self.base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise RegistryError(f"{exc.code} {exc.reason}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RegistryError(f"could not reach registry at {url}: {exc.reason}") from exc

    def push(self, passport: dict) -> str:
        res = self._request("POST", "/passports", body=passport)
        return res.get("id", "")

    def pull(self, pid: str) -> Optional[dict]:
        return self._request("GET", f"/passports/{pid}")

    def list(self) -> list[dict]:
        res = self._request("GET", "/passports")
        return res.get("passports", []) if isinstance(res, dict) else []


class RegistryError(Exception):
    """Network/registry-side failure."""
