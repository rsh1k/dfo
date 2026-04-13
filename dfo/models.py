"""
dfo/models.py
=============
Shared data models used across all DFO modules.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FindingCategory(Enum):
    NETWORK = "network"
    MEMORY = "memory"
    BINARY = "binary"
    DISK = "disk"


class NISTPhase(Enum):
    COLLECTION = "Collection"
    EXAMINATION = "Examination"
    ANALYSIS = "Analysis"
    REPORTING = "Reporting"


class SeverityTier(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: float) -> SeverityTier:
        if score >= 0.8:
            return cls.CRITICAL
        elif score >= 0.6:
            return cls.HIGH
        elif score >= 0.3:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class ForensicFinding:
    """Normalized artifact record produced by any engine adapter."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: FindingCategory = FindingCategory.NETWORK
    engine: str = ""
    timestamp: str = ""
    title: str = ""
    description: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    ioc_matches: list[str] = field(default_factory=list)
    persistence_indicators: list[str] = field(default_factory=list)
    exfil_indicators: list[str] = field(default_factory=list)
    severity_score: float = 0.0

    @property
    def severity(self) -> SeverityTier:
        return SeverityTier.from_score(self.severity_score)

    def summary_line(self, max_desc: int = 60) -> str:
        desc = self.description
        if len(desc) > max_desc:
            desc = desc[:max_desc] + "…"
        return (
            f"[{self.severity.value}] {self.severity_score:.3f} | "
            f"{self.category.value:8s} | {self.engine:13s} | "
            f"{self.title} — {desc}"
        )


@dataclass
class CustodyEntry:
    """Single entry in the chain-of-custody log."""
    timestamp: str
    action: str
    actor: str
    artifact_id: str
    sha256_hash: str
    description: str
    nist_phase: str


@dataclass
class DFOConfig:
    """Runtime configuration."""
    case_id: str = "UNSET"
    analyst: str = "auto"
    log_dir: str = "./cases"
    ioc_path: str | None = None
    chroma_dir: str = "./chroma_db"
    embedding_model: str = "all-MiniLM-L6-v2"
    scorer_weights: dict[str, float] = field(default_factory=lambda: {
        "ioc": 0.40,
        "persistence": 0.30,
        "exfiltration": 0.30,
    })
