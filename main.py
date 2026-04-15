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
