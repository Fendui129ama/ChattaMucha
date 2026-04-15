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
    return "application/octet-stream"


def _strip_0x(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("0x") or s.startswith("0X"):
        return s[2:]
    return s


def _is_hex(s: str) -> bool:
    if not s:
        return False
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


def _as_bytes_exact(hex_str: str, nbytes: int, field: str) -> bytes:
    raw = _strip_0x(hex_str)
    if len(raw) != nbytes * 2 or not _is_hex(raw):
        _raise(400, "bad_hex", f"{field} must be {nbytes} bytes hex", field=field, expected_bytes=nbytes)
    return bytes.fromhex(raw)


def _as_address_bytes(addr: str, field: str = "address") -> bytes:
    raw = _strip_0x(addr)
    if len(raw) != 40 or not _is_hex(raw):
        _raise(400, "bad_address", f"{field} must be 20-byte hex", field=field)
    b = bytes.fromhex(raw)
    if len(b) != 20:
        _raise(400, "bad_address", f"{field} must be 20 bytes", field=field)
    return b


def _checksum_address_if_possible(addr: str) -> Dict[str, Any]:
    """
    Returns:
      { "input": ..., "checksum": ..., "kind": "eip55"|"lowercase", "keccak_available": bool }
    """
    raw = "0x" + _strip_0x(addr).lower()
    try:
        from web3 import Web3  # type: ignore

        return {
            "input": addr,
            "checksum": Web3.to_checksum_address(raw),
            "kind": "eip55",
            "keccak_available": True,
        }
    except Exception:
        return {
            "input": addr,
            "checksum": raw,
            "kind": "lowercase",
            "keccak_available": False,
        }


def _u256(x: Union[str, int], field: str) -> int:
    try:
        if isinstance(x, str):
            x = x.strip()
            if x.startswith("0x") or x.startswith("0X"):
                v = int(x, 16)
            else:
                v = int(x, 10)
        else:
            v = int(x)
    except Exception:
        _raise(400, "bad_int", f"{field} must be integer-like", field=field)
    if v < 0 or v >= 2**256:
        _raise(400, "bad_int", f"{field} out of uint256 range", field=field)
    return v


def _u64(x: Union[str, int], field: str) -> int:
    v = _u256(x, field)
    if v >= 2**64:
        _raise(400, "bad_int", f"{field} out of uint64 range", field=field)
    return v


def _u32(x: Union[str, int], field: str) -> int:
    v = _u256(x, field)
    if v >= 2**32:
        _raise(400, "bad_int", f"{field} out of uint32 range", field=field)
    return v


def _pack_uint(v: int, nbytes: int) -> bytes:
    return int(v).to_bytes(nbytes, "big", signed=False)


def abi_encode_packed_capsule_id(
    owner: str,
    asset: str,
    bounty_wei: Union[str, int],
    content_hash_hex: str,
    open_at: Union[str, int],
    final_earliest_at: Union[str, int],
    final_latest_at: Union[str, int],
    challenge_latest_at: Union[str, int],
    steward_quorum: Union[str, int],
) -> bytes:
    """
    Mirrors Solidity:
      keccak256(abi.encodePacked(owner, asset, bounty, contentHash, openAt, finalEarliestAt, finalLatestAt, challengeLatestAt, stewardQuorum))
    with types:
      address,address,uint256,bytes32,uint64,uint64,uint64,uint64,uint32
    """
    b_owner = _as_address_bytes(owner, "owner")
    b_asset = _as_address_bytes(asset, "asset")
    bounty = _u256(bounty_wei, "bounty_wei")
    content = _as_bytes_exact(content_hash_hex, 32, "content_hash_hex")
    o = _u64(open_at, "open_at")
    fe = _u64(final_earliest_at, "final_earliest_at")
    fl = _u64(final_latest_at, "final_latest_at")
    cl = _u64(challenge_latest_at, "challenge_latest_at")
    q = _u32(steward_quorum, "steward_quorum")
    return b"".join(
        [
            b_owner,
            b_asset,
            _pack_uint(bounty, 32),
            content,
            _pack_uint(o, 8),
            _pack_uint(fe, 8),
            _pack_uint(fl, 8),
            _pack_uint(cl, 8),
            _pack_uint(q, 4),
        ]
    )


def abi_encode_single(value: Any, typ: str, field: str) -> bytes:
    """
    Minimal ABI encoder for the fixed types used by Ox_Futurino callable methods.
    Supported types: address, uint256, uint64, uint32, bytes32, bool
    """
    if typ == "address":
        b = _as_address_bytes(str(value), field)
        return b"\x00" * 12 + b
    if typ == "uint256":
        v = _u256(value, field)
        return _pack_uint(v, 32)
    if typ == "uint64":
        v = _u64(value, field)
        return _pack_uint(v, 32)  # ABI word
    if typ == "uint32":
        v = _u32(value, field)
        return _pack_uint(v, 32)  # ABI word
    if typ == "bytes32":
        return _as_bytes_exact(str(value), 32, field)
    if typ == "bool":
        v = bool(value)
        return _pack_uint(1 if v else 0, 32)
    _raise(400, "codec_unsupported", f"Unsupported ABI type: {typ}", type=typ, field=field)
    raise AssertionError("unreachable")


def function_selector(signature: str) -> bytes:
    kind, hx = _keccak_or_placeholder(signature.encode("utf-8"))
    # if placeholder hashing is used, selector is not valid for EVM; we still show it clearly
    return bytes.fromhex(hx)[:4], kind


def encode_calldata(signature: str, arg_types: List[str], arg_values: List[Any]) -> Dict[str, Any]:
    if len(arg_types) != len(arg_values):
        _raise(400, "bad_input", "arg_types and arg_values length mismatch")
    sel, kind = function_selector(signature)
    words = []
    for i, (t, v) in enumerate(zip(arg_types, arg_values)):
        words.append(abi_encode_single(v, t, f"arg[{i}]"))
    data = sel + b"".join(words)
    return {
        "selector_hash_kind": kind,
        "signature": signature,
        "selector_hex": "0x" + sel.hex(),
        "calldata_hex": "0x" + data.hex(),
        "calldata_bytes": len(data),
    }


def _abi_encode_struct(types_: List[str], values_: List[Any]) -> bytes:
    # for our fixed-only usage, ABI encoding == concatenated 32-byte words
    if len(types_) != len(values_):
        _raise(400, "bad_input", "types/values mismatch")
    out = []
    for i, (t, v) in enumerate(zip(types_, values_)):
        out.append(abi_encode_single(v, t, f"struct[{i}]"))
    return b"".join(out)


def _bytes32_hex(b: bytes) -> str:
    if len(b) != 32:
        _raise(500, "internal", "expected 32-byte value")
    return "0x" + b.hex()


def futurino_capsule_open_digest(
    domain_salt_hex: str,
    owner: str,
    asset: str,
    bounty: Union[str, int],
    content_hash_hex: str,
    final_earliest_at: Union[str, int],
    final_latest_at: Union[str, int],
    challenge_latest_at: Union[str, int],
    steward_quorum: Union[str, int],
    owner_nonce: Union[str, int],
    chain_id: Union[str, int],
    verifying_contract: str,
) -> Dict[str, Any]:
    """
    Mirrors Solidity:
      bytes32 structHash = keccak256(abi.encode(TYPEHASH, ...fields..., ownerNonce, chainId, verifyingContract));
      digest = keccak256("\x19\x01" || DOMAIN_SALT || structHash);

    Note: DOMAIN_SALT is a bytes32 in Ox_Futurino.
    """
    domain_salt = _as_bytes_exact(domain_salt_hex, 32, "domain_salt_hex")

    type_str = (
        "CapsuleOpen(address owner,address asset,uint256 bounty,bytes32 contentHash,uint64 finalEarliestAt,uint64 finalLatestAt,uint64 challengeLatestAt,uint32 stewardQuorum,uint256 ownerNonce,uint256 chainId,address verifyingContract)"
    )
    kind_t, typehash = _keccak_bytes_or_placeholder(type_str.encode("utf-8"))

    types_ = [
        "bytes32",
        "address",
        "address",
        "uint256",
        "bytes32",
        "uint64",
        "uint64",
        "uint64",
        "uint32",
        "uint256",
        "uint256",
        "address",
    ]
    values_ = [
        _bytes32_hex(typehash),
        owner,
        asset,
        str(bounty),
        content_hash_hex,
        int(_u64(final_earliest_at, "final_earliest_at")),
        int(_u64(final_latest_at, "final_latest_at")),
        int(_u64(challenge_latest_at, "challenge_latest_at")),
        int(_u32(steward_quorum, "steward_quorum")),
        str(_u256(owner_nonce, "owner_nonce")),
        str(_u256(chain_id, "chain_id")),
        verifying_contract,
    ]

    enc = _abi_encode_struct(types_, values_)
    kind_s, struct_hash = _keccak_bytes_or_placeholder(enc)

    prefix = b"\x19\x01" + domain_salt + struct_hash
    kind_d, digest = _keccak_bytes_or_placeholder(prefix)

    # if keccak is missing, everything becomes a consistent placeholder — still useful for UI wiring
    return {
        "hash_kind": kind_d,
        "typehash_kind": kind_t,
        "structhash_kind": kind_s,
        "typehash": _bytes32_hex(typehash),
        "struct_hash": _bytes32_hex(struct_hash),
        "digest": _bytes32_hex(digest),
    }


def compute_capsule_id(draft: Dict[str, Any], open_at: Optional[int] = None) -> Dict[str, Any]:
    if open_at is None:
        open_at = int(time.time())
    packed = abi_encode_packed_capsule_id(
        owner=str(draft["owner_address"]),
        asset=str(draft["asset_address"]),
        bounty_wei=str(draft["bounty_wei"]),
        content_hash_hex=str(draft["content_hash_hex"]),
        open_at=open_at,
        final_earliest_at=int(draft["final_earliest_at"]),
        final_latest_at=int(draft["final_latest_at"]),
        challenge_latest_at=int(draft["challenge_latest_at"]),
        steward_quorum=int(draft["steward_quorum"]),
    )
    kind, hx = _keccak_or_placeholder(packed)
    return {"hash_kind": kind, "capsule_id_hex": "0x" + hx, "open_at": open_at, "packed_bytes": len(packed)}


class ChattaMuchaHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ChattaMuchaHTTP/1.0"

    def _db(self) -> Db:
        return self.server.db  # type: ignore[attr-defined]

    def _route(self) -> Tuple[str, Dict[str, str]]:
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        qs = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        return path, qs

    def log_message(self, fmt: str, *args: Any) -> None:
        # quieter than default, still includes essentials
        sys.stdout.write("[%s] %s\n" % (_dt.datetime.now().strftime("%H:%M:%S"), (fmt % args)))

    def _handle_api_error(self, e: ApiError) -> None:
        _send_json(
            self,
            e.status,
            {
                "ok": False,
                "error": {"code": e.code, "message": e.message, "details": e.details},
                "at": _now_utc(),
            },
        )

    def _handle_unexpected(self, e: Exception) -> None:
        _send_json(
            self,
            500,
            {
                "ok": False,
                "error": {"code": "internal", "message": "Unexpected error", "details": {"type": type(e).__name__}},
                "at": _now_utc(),
            },
        )

    def do_GET(self) -> None:
        try:
            path, qs = self._route()
            if path.startswith("/api/"):
                self._api_get(path, qs)
                return
            self._serve_ui(path)
        except ApiError as e:
            self._handle_api_error(e)
        except Exception as e:
            traceback.print_exc()
            self._handle_unexpected(e)

    def do_POST(self) -> None:
        try:
            path, qs = self._route()
            if not path.startswith("/api/"):
                _raise(404, "not_found", "Unknown endpoint")
            body = _read_body(self)
            data = _parse_json(body)
            self._api_post(path, qs, data)
        except ApiError as e:
            self._handle_api_error(e)
        except Exception as e:
            traceback.print_exc()
            self._handle_unexpected(e)

    def _api_get(self, path: str, qs: Dict[str, str]) -> None:
        if path == "/api/health":
            _send_json(
                self,
                200,
                {
                    "ok": True,
                    "app": APP_NAME,
                    "at": _now_utc(),
                    "ui_dir": str(_ui_dir()),
                    "db_path": str(_db_path()),
                    "python": sys.version,
                    "features": FEATURES,
                    "hashing": {"keccak_available": _try_web3_keccak(b"t") is not None},
                },
            )
            return

        if path == "/api/drafts":
            limit = _safe_int(qs.get("limit"), 50)
            _send_json(self, 200, {"ok": True, "drafts": self._db().list_drafts(limit=limit)})
            return

        if path == "/api/activity":
            capsule_id = (qs.get("capsule_id") or "").strip()
            if not capsule_id:
                _raise(400, "bad_input", "capsule_id required")
            limit = _safe_int(qs.get("limit"), 200)
            _send_json(self, 200, {"ok": True, "items": self._db().list_activity(capsule_id=capsule_id, limit=limit)})
            return

        if path == "/api/config":
            db = self._db()
            cfg = {
                "chain_id": _safe_int(db.kv_get("chain_id", str(DEFAULT_CHAIN_ID)), DEFAULT_CHAIN_ID),
                "verifying_contract": db.kv_get("verifying_contract", DEFAULT_VERIFYING_CONTRACT) or DEFAULT_VERIFYING_CONTRACT,
                "domain_salt_hex": db.kv_get("domain_salt_hex", DEFAULT_DOMAIN_SALT_HEX) or DEFAULT_DOMAIN_SALT_HEX,
            }
            cfg["verifying_contract_checksum"] = _checksum_address_if_possible(cfg["verifying_contract"])
            _send_json(self, 200, {"ok": True, "config": cfg})
