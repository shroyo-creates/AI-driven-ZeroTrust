"""Append-only, hash-chained audit log.

Each entry stores the SHA-256 of the previous entry, so editing or deleting a
past decision breaks the chain and :meth:`AuditLog.verify` reports where.
Entries can also be mirrored to a JSONL file for a SIEM to ingest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from threading import Lock

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict] = []
        self._lock = Lock()

    @staticmethod
    def _digest(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            entry = {"seq": len(self.entries), "kind": kind, "prev": prev, "data": data}
            entry["hash"] = self._digest(entry)
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as fh:
                    fh.write(json.dumps(entry, default=str) + "\n")
            return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, index of first bad entry)."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e["prev"] != prev or e["hash"] != self._digest(e):
                return False, i
            prev = e["hash"]
        return True, None

    def tail(self, n: int = 50, kind: str | None = None) -> list[dict]:
        items = [e for e in self.entries if kind is None or e["kind"] == kind]
        return items[-n:]
