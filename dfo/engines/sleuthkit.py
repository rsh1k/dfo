"""
dfo/engines/sleuthkit.py
========================
Disk / filesystem forensics via SleuthKit CLI tools.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dfo.engines.base import BaseEngineAdapter
from dfo.models import ForensicFinding, FindingCategory


class SleuthKitAdapter(BaseEngineAdapter):
    """
    Wraps SleuthKit CLI (mmls, fls, icat) for disk image analysis.
    """

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr",
        ".7z", ".rar", ".zip", ".enc", ".pgp",
    }

    def analyze(self, evidence_path: Path, **kwargs) -> list[ForensicFinding]:
        self._check_tool("mmls")
        self._check_tool("fls")

        artifact_id = self.custody.register_artifact(
            evidence_path, self.actor,
            "Disk image ingested for filesystem forensics",
            nist_phase="Collection"
        )
        findings: list[ForensicFinding] = []

        # Partition layout
        mmls_out = self._run_cli(["mmls", str(evidence_path)])
        self.custody.log_action(
            artifact_id, "EXAMINED", self.actor,
            "Partition table extracted via mmls",
            nist_phase="Examination"
        )
        findings.append(ForensicFinding(
            category=FindingCategory.DISK,
            engine="sleuthkit",
            timestamp=datetime.now(timezone.utc).isoformat(),
            title="Disk [partition table]",
            description=mmls_out.strip()[:200],
            raw_data={"tool": "mmls", "output": mmls_out[:2000]},
        ))

        # Recursive file listing
        offset = kwargs.get("partition_offset", "0")
        fls_out = self._run_cli([
            "fls", "-r", "-p", "-o", str(offset), str(evidence_path)
        ])
        self.custody.log_action(
            artifact_id, "EXAMINED", self.actor,
            f"Recursive file listing at offset {offset}",
            nist_phase="Examination"
        )

        for line in fls_out.strip().splitlines():
            deleted = line.startswith("*")
            finding = ForensicFinding(
                category=FindingCategory.DISK,
                engine="sleuthkit",
                timestamp=datetime.now(timezone.utc).isoformat(),
                title="Disk [file entry]",
                description=line.strip(),
                raw_data={"deleted": deleted, "entry": line.strip()},
            )

            if deleted:
                finding.persistence_indicators.append("deleted_file_recovered")

            lower = line.lower()
            for ext in self.SUSPICIOUS_EXTENSIONS:
                if ext in lower:
                    finding.persistence_indicators.append(
                        f"suspicious_extension:{ext}"
                    )
                    break

            findings.append(finding)

        return findings
