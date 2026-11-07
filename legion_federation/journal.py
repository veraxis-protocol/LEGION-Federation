# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""Append-only, hash-chained JSONL journal. One journal per owner process; never shared."""
import json
import os
import threading
import time

from .canonical import canonical, sha256_hex


class Journal:
    def __init__(self, path, owner_id):
        self.path, self.owner_id = path, owner_id
        self._lock = threading.Lock()
        self._seq, self._prev = 0, "0" * 64
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if os.path.exists(path):
            for line in open(path, encoding="utf-8"):
                rec = json.loads(line)
                self._seq, self._prev = rec["seq"], rec["hash"]

    def emit(self, kind, **data):
        with self._lock:
            self._seq += 1
            rec = {"seq": self._seq, "t": time.time(), "owner_id": self.owner_id, "kind": kind,
                   "data": data, "prev": self._prev}
            rec["hash"] = sha256_hex(canonical({k: v for k, v in rec.items() if k != "hash"}))
            self._prev = rec["hash"]
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            return rec


def verify_chain(path):
    prev, n = "0" * 64, 0
    for line in open(path, encoding="utf-8"):
        rec = json.loads(line)
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec["prev"] != prev or sha256_hex(canonical(body)) != rec["hash"]:
            return False, n
        prev, n = rec["hash"], n + 1
    return True, n
