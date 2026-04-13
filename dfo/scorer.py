"""
dfo/scorer.py
=============
NIST SP 800-61 Rev. 2 Artifact Scorer.
Weighted scoring: IOC=40%, Persistence=30%, Exfiltration=30%.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from dfo.models import ForensicFinding
from dfo.terminal import console, print_info


class ArtifactScorer:
    """
    Weighted scoring engine aligned with NIST SP 800-61 Rev. 2.
    Higher score = more significant finding.
    """

    DEFAULT_WEIGHTS = {
        "ioc": 0.40,
        "persistence": 0.30,
        "exfiltration": 0.30,
    }

    def __init__(self, ioc_database: Optional[dict] = None,
                 weights: Optional[dict] = None):
        self.weights = weights or self.DEFAULT_WEIGHTS
        self.ioc_db: dict[str, set[str]] = ioc_database or {
            "ip": set(),
            "domain": set(),
            "hash": set(),
            "mutex": set(),
            "useragent": set(),
        }

    def load_iocs_from_file(self, path: Path):
        """Load IOCs from a JSON file: {"ip": [...], "domain": [...], ...}"""
        with open(path) as f:
            data = json.load(f)
        total = 0
        for key, values in data.items():
            self.ioc_db.setdefault(key, set()).update(values)
            total += len(values)
        print_info(f"Loaded [bold]{total}[/bold] IOCs across "
                   f"[bold]{len(data)}[/bold] categories")

    def score(self, finding: ForensicFinding) -> float:
        """Score a single finding. Returns 0.0–1.0."""
        ioc_score = self._check_iocs(finding)
        pers_score = min(len(finding.persistence_indicators) / 3.0, 1.0)
        exfil_score = min(len(finding.exfil_indicators) / 3.0, 1.0)

        total = (
            self.weights["ioc"] * ioc_score
            + self.weights["persistence"] * pers_score
            + self.weights["exfiltration"] * exfil_score
        )
        finding.severity_score = round(total, 4)
        return finding.severity_score

    def score_all(self, findings: list[ForensicFinding]) -> list[ForensicFinding]:
        """Score all findings and return sorted by severity (desc)."""
        for f in findings:
            self.score(f)
        return sorted(findings, key=lambda x: x.severity_score, reverse=True)

    def _check_iocs(self, finding: ForensicFinding) -> float:
        """Scan raw_data for known IOC matches."""
        raw_str = json.dumps(finding.raw_data).lower()
        matches = []
        for ioc_type, indicators in self.ioc_db.items():
            for indicator in indicators:
                if indicator.lower() in raw_str:
                    matches.append(f"{ioc_type}:{indicator}")
        finding.ioc_matches = matches
        return min(len(matches) / 2.0, 1.0)
