"""
ChattaMucha
-----------
Local Python companion app for Ox_Futurino (Solidity).

Goals:
- Zero external dependencies required (runs on stdlib).
- Provides a tiny JSON API + serves the ChowBueno UI.
- Stores local "capsule drafts" and "activity log" in SQLite.

Run:
  python ChattaMucha.py

Open:
  http://127.0.0.1:8844/
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as _dt
import hashlib
import http.server
import json
import os
import secrets
import shutil
import signal
import sqlite3
import sys
import threading
import time
import traceback
import types
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union


APP_NAME = "ChattaMucha"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8844
DB_FILENAME = "chattamucha.sqlite3"
UI_DIRNAME = "ChowBueno"

MAX_BODY_BYTES = 2 * 1024 * 1024
JSON_CT = "application/json; charset=utf-8"
TEXT_CT = "text/plain; charset=utf-8"

FEATURES = {
    "dependency_free": True,
    "real_keccak_if_web3": True,
    "abi_codec": True,
    "evm_calldata_builder": True,
    "eip712_digest_builder": True,
}

# Ox_Futurino: handy defaults (can be overwritten via /api/config)
DEFAULT_CHAIN_ID = 1
DEFAULT_VERIFYING_CONTRACT = "0x0000000000000000000000000000000000000000"
DEFAULT_DOMAIN_SALT_HEX = "0x" + "11" * 32


def _now_utc() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _try_web3_keccak(data: bytes) -> Optional[bytes]:
    try:
        # web3 is optional; requirements.txt already includes it in this workspace
        from web3 import Web3  # type: ignore

        return Web3.keccak(data)
    except Exception:
        return None


def _keccak_or_placeholder(data: bytes) -> Tuple[str, str]:
    """
    Returns (kind, hexNo0x)
    - kind == "keccak256" if web3 is available
    - kind == "sha256-not-keccak" if dependency-free fallback
    """
    k = _try_web3_keccak(data)
    if k is not None:
        return ("keccak256", k.hex())
    return ("sha256-not-keccak", _sha256_hex(b"not-keccak::" + data))


def _keccak_bytes_or_placeholder(data: bytes) -> Tuple[str, bytes]:
    k = _try_web3_keccak(data)
    if k is not None:
        return ("keccak256", k)
    return ("sha256-not-keccak", hashlib.sha256(b"not-keccak::" + data).digest())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _json_dumps(obj: Any) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        if isinstance(x, bool):
            return default
        return int(x)
    except Exception:
        return default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name, "").strip()
    if not v:
        return default
    return _safe_int(v, default=default)


def _env_str(name: str, default: str) -> str:
    v = os.getenv(name, "").strip()
    return v or default


@dataclasses.dataclass(frozen=True)
class ApiError(Exception):
    status: int
    code: str
    message: str
    details: Dict[str, Any] = dataclasses.field(default_factory=dict)


def _raise(status: int, code: str, message: str, **details: Any) -> None:
    raise ApiError(status=status, code=code, message=message, details=dict(details))


class Db:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._migrate()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()

    def _migrate(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS capsule_drafts (
                  id TEXT PRIMARY KEY,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  owner_address TEXT NOT NULL,
                  asset_address TEXT NOT NULL,
                  bounty_wei TEXT NOT NULL,
                  content_hash_hex TEXT NOT NULL,
                  final_earliest_at INTEGER NOT NULL,
                  final_latest_at INTEGER NOT NULL,
                  challenge_latest_at INTEGER NOT NULL,
                  steward_quorum INTEGER NOT NULL,
                  notes TEXT NOT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS app_kv (
                  k TEXT PRIMARY KEY,
                  v TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS activity_log (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT,
                  at TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  capsule_id TEXT NOT NULL,
                  payload_json TEXT NOT NULL
                );
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_activity_capsule ON activity_log(capsule_id, seq);")
            self._conn.commit()

    def upsert_draft(self, draft: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_utc()
        draft_id = str(draft.get("id") or "")
        if not draft_id:
            draft_id = "d_" + _b64url(secrets.token_bytes(18))
        owner = str(draft.get("owner_address") or "")
        asset = str(draft.get("asset_address") or "")
        bounty = str(draft.get("bounty_wei") or "0")
        chash = str(draft.get("content_hash_hex") or "")
        fe = _safe_int(draft.get("final_earliest_at"), 0)
        fl = _safe_int(draft.get("final_latest_at"), 0)
        cl = _safe_int(draft.get("challenge_latest_at"), 0)
        q = _safe_int(draft.get("steward_quorum"), 0)
        notes = str(draft.get("notes") or "")

        if not owner or not asset or not chash:
            _raise(400, "bad_input", "Missing required fields", required=["owner_address", "asset_address", "content_hash_hex"])
        if q <= 0:
            _raise(400, "bad_input", "steward_quorum must be > 0")
        if fe <= 0 or fl <= 0 or cl <= 0:
            _raise(400, "bad_input", "Time fields must be positive unix timestamps")
        if not (fe < fl and fe < cl <= fl):
            _raise(400, "bad_input", "Invalid time window ordering")

        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT id FROM capsule_drafts WHERE id = ?;", (draft_id,))
            exists = cur.fetchone() is not None
            if not exists:
                cur.execute(
                    """
                    INSERT INTO capsule_drafts
                    (id, created_at, updated_at, owner_address, asset_address, bounty_wei, content_hash_hex,
                     final_earliest_at, final_latest_at, challenge_latest_at, steward_quorum, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (draft_id, now, now, owner, asset, bounty, chash, fe, fl, cl, q, notes),
                )
            else:
                cur.execute(
                    """
                    UPDATE capsule_drafts
                      SET updated_at = ?,
                          owner_address = ?,
                          asset_address = ?,
                          bounty_wei = ?,
                          content_hash_hex = ?,
                          final_earliest_at = ?,
                          final_latest_at = ?,
                          challenge_latest_at = ?,
                          steward_quorum = ?,
                          notes = ?
                      WHERE id = ?;
                    """,
                    (now, owner, asset, bounty, chash, fe, fl, cl, q, notes, draft_id),
                )
            self._conn.commit()

        return self.get_draft(draft_id)

    def get_draft(self, draft_id: str) -> Dict[str, Any]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM capsule_drafts WHERE id = ?;", (draft_id,))
            row = cur.fetchone()
        if row is None:
            _raise(404, "not_found", "Draft not found", id=draft_id)
        return dict(row)

    def list_drafts(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM capsule_drafts ORDER BY updated_at DESC LIMIT ?;", (limit,))
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    def delete_draft(self, draft_id: str) -> Dict[str, Any]:
        d = self.get_draft(draft_id)
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM capsule_drafts WHERE id = ?;", (draft_id,))
            self._conn.commit()
        return d

    def log(self, kind: str, capsule_id: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO activity_log(at, kind, capsule_id, payload_json) VALUES (?, ?, ?, ?);",
                (_now_utc(), kind, capsule_id, json.dumps(payload, ensure_ascii=False)),
            )
            self._conn.commit()

    def list_activity(self, capsule_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 2000))
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT seq, at, kind, capsule_id, payload_json FROM activity_log WHERE capsule_id = ? ORDER BY seq DESC LIMIT ?;",
                (capsule_id, limit),
            )
            rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "seq": int(r["seq"]),
                    "at": r["at"],
                    "kind": r["kind"],
                    "capsule_id": r["capsule_id"],
                    "payload": json.loads(r["payload_json"] or "{}"),
                }
            )
        return out

    def kv_get(self, k: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT v FROM app_kv WHERE k = ?;", (k,))
            row = cur.fetchone()
        if row is None:
            return default
        return str(row["v"])

    def kv_set(self, k: str, v: str) -> None:
        now = _now_utc()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("INSERT INTO app_kv(k, v, updated_at) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at;", (k, v, now))
            self._conn.commit()


def _workspace_root() -> Path:
    # this file lives at <root>/ChattaMucha/ChattaMucha.py
    return Path(__file__).resolve().parents[1]


def _ui_dir() -> Path:
    return _workspace_root() / UI_DIRNAME


def _db_path() -> Path:
    return Path(__file__).resolve().parent / DB_FILENAME


def _read_body(handler: http.server.BaseHTTPRequestHandler) -> bytes:
    cl = handler.headers.get("Content-Length", "").strip()
    if not cl:
        return b""
    n = _safe_int(cl, -1)
    if n < 0 or n > MAX_BODY_BYTES:
        _raise(413, "payload_too_large", f"Body too large (limit {MAX_BODY_BYTES} bytes)")
    return handler.rfile.read(n)


def _parse_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as e:
        _raise(400, "bad_json", "Invalid JSON", error=str(e))


def _send(handler: http.server.BaseHTTPRequestHandler, status: int, body: bytes, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _send_json(handler: http.server.BaseHTTPRequestHandler, status: int, obj: Any) -> None:
    _send(handler, status, _json_dumps(obj), JSON_CT)


def _send_text(handler: http.server.BaseHTTPRequestHandler, status: int, text: str) -> None:
    _send(handler, status, (text + "\n").encode("utf-8"), TEXT_CT)


def _guess_ct(path: Path) -> str:
    p = path.name.lower()
    if p.endswith(".html"):
        return "text/html; charset=utf-8"
    if p.endswith(".css"):
        return "text/css; charset=utf-8"
    if p.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if p.endswith(".json"):
        return JSON_CT
    if p.endswith(".svg"):
        return "image/svg+xml"
    if p.endswith(".png"):
        return "image/png"
    if p.endswith(".jpg") or p.endswith(".jpeg"):
        return "image/jpeg"
