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
