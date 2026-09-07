"""Bounds and deterministic encoding for the SZL Mesh Convergence Lab."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

MAX_REPLICAS = 8
MAX_OPERATIONS = 64
MAX_REQUEST_BYTES = 256 * 1024
MAX_KEY_BYTES = 128
MAX_VALUE_BYTES = 4096
MAX_DOC_ID_BYTES = 96
MAX_NODE_ID_BYTES = 64
MAX_LAMPORT = 2_147_483_647
DOC_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
CONTROLLED_FILES = (
    "lab/app.py",
    "lab/config.py",
    "lab/simulator.py",
    "lab/static/index.html",
    "lab/static/app.js",
    "lab/static/styles.css",
    "lab/static/responsive.css",
    "lab/requirements.txt",
    "lab/constraints.txt",
    "lab/Dockerfile",
)


def canonical_bytes(value: Any) -> bytes:
    """Encode JSON deterministically and reject NaN/Infinity."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
