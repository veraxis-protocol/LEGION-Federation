# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""Canonical JSON, hashing and time helpers shared by every Federation component."""
import hashlib
import json
import time
import uuid


def canonical(obj) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8, no NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = canonical(data)
    return hashlib.sha256(data).hexdigest()


def file_sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def now() -> float:
    return time.time()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"
