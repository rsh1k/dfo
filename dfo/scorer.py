"""
dfo/scorer.py
=============
NIST SP 800-61 Rev. 2 Artifact Scorer — Enterprise Edition.

Scoring formula (configurable weights):
  Total = (w_ioc × IOC) + (w_persistence × Persistence) +
          (w_exfil × Exfiltration) + (w_yara × YARA) +
          (w_mitre × MITRE) + (w_ai × AI Risk)
"""

from __future__ import annotations

from dfo.models import ForensicFinding
from dfo.terminal import print_info


class ArtifactScorer:
    """Enhanced weighted scoring with YARA, MITRE, and AI components."""

    DEFAULT_WEIGHTS = {
        "ioc": 0.25,
        "persistence": 0.20,
        "exfiltration": 0.20,
        "yara": 0.15,
        "mitre": 0.10,
        "ai_risk": 0.10,
    }

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or self.DEFAULT_WEIGHTS

    def score(self, finding: ForensicFinding) -> float:
        """Score a single finding. Returns 0.0–1.0."""
        w = self.weights

        ioc_score = min(len(finding.ioc_matches) / 2.0, 1.0)
        pers_score = min(len(finding.persistence_indicators) / 3.0, 1.0)
        exfil_score = min(len(finding.exfil_indicators) / 3.0, 1.0)

        # YARA score: any match is significant
        yara_score = min(len(finding.yara_matches) / 1.0, 1.0)

        # MITRE score: based on confidence of mapped techniques
        mitre_score = 0.0
        if finding.mitre_mappings:
            avg_conf = sum(
                m.confidence for m in finding.mitre_mappings
            ) / len(finding.mitre_mappings)
            mitre_score = min(avg_conf * 1.5, 1.0)

        # AI risk: parsed from AI analysis if available
        ai_score = 0.0
        if finding.ai_summary:
            lower = finding.ai_summary.lower()
            if "critical" in lower or "malicious" in lower:
                ai_score = 1.0
            elif "high" in lower or "suspicious" in lower:
                ai_score = 0.7
            elif "medium" in lower:
                ai_score = 0.4

        total = (
            w.get("ioc", 0) * ioc_score
            + w.get("persistence", 0) * pers_score
            + w.get("exfiltration", 0) * exfil_score
            + w.get("yara", 0) * yara_score
            + w.get("mitre", 0) * mitre_score
            + w.get("ai_risk", 0) * ai_score
        )
        finding.severity_score = round(min(total, 1.0), 4)
        return finding.severity_score

    def score_all(self, findings: list[ForensicFinding]) -> list[ForensicFinding]:
        for f in findings:
            self.score(f)
        return sorted(findings, key=lambda x: x.severity_score, reverse=True)
