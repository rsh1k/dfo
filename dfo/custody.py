"""
dfo/custody.py
==============
Chain of Custody log — NIST SP 800-86 compliant.
Immutable, append-only JSONL log with SHA-256 hashing.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dfo.models import CustodyEntry
from dfo.terminal import console, print_success


class ChainOfCustody:
    """
    Immutable, append-only chain-of-custody log.
    Satisfies NIST SP 800-86 §4 requirements for evidence handling.
    """

    def __init__(self, case_id: str, log_dir: Path):
        self.case_id = case_id
        self.log_path = log_dir / f"coc_{case_id}.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: list[CustodyEntry] = []
        self._load_existing()

    def _load_existing(self):
        """Reload entries from disk on init."""
        if self.log_path.exists():
            for line in self.log_path.read_text().splitlines():
                if line.strip():
                    d = json.loads(line)
                    self._entries.append(CustodyEntry(**d))

    def register_artifact(self, filepath: Path, actor: str,
                          description: str, nist_phase: str) -> str:
        """Hash file, assign UUID, append to log. Returns artifact_id."""
        artifact_id = str(uuid.uuid4())
        sha256 = self._hash_file(filepath)
        entry = CustodyEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action="REGISTERED",
            actor=actor,
            artifact_id=artifact_id,
            sha256_hash=sha256,
            description=description,
            nist_phase=nist_phase,
        )
        self._append(entry)
        print_success(
            f"Artifact registered: [muted]{artifact_id[:12]}…[/muted] "
            f"SHA256=[muted]{sha256[:16]}…[/muted]"
        )
        return artifact_id

    def log_action(self, artifact_id: str, action: str,
                   actor: str, description: str, nist_phase: str):
        """Log an examination/analysis action against an artifact."""
        entry = CustodyEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            actor=actor,
            artifact_id=artifact_id,
            sha256_hash="N/A",
            description=description,
            nist_phase=nist_phase,
        )
        self._append(entry)

    def _hash_file(self, path: Path) -> str:
        """Compute SHA-256 hash of an evidence file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _append(self, entry: CustodyEntry):
        """Append entry to in-memory list and persist to JSONL."""
        self._entries.append(entry)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry.__dict__) + "\n")
