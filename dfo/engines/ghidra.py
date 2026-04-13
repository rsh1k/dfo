"""
dfo/engines/ghidra.py
=====================
Binary / static analysis via Ghidra headless mode.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dfo.engines.base import BaseEngineAdapter
from dfo.models import ForensicFinding, FindingCategory


class GhidraAdapter(BaseEngineAdapter):
    """
    Runs Ghidra in headless mode with post-analysis scripts
    that export function names, strings, and import tables.
    """

    def analyze(self, evidence_path: Path, **kwargs) -> list[ForensicFinding]:
        self._check_tool("analyzeHeadless")

        project_dir = kwargs.get("project_dir", Path("/tmp/ghidra_dfo"))
        project_dir.mkdir(parents=True, exist_ok=True)

        artifact_id = self.custody.register_artifact(
            evidence_path, self.actor,
            "Binary ingested for static disassembly",
            nist_phase="Collection"
        )

        cmd = [
            "analyzeHeadless", str(project_dir), "DFOProject",
            "-import", str(evidence_path),
            "-postScript", "ExportFunctions.java",
            "-deleteProject",
            "-scriptlog", str(project_dir / "script.log"),
        ]
        raw = self._run_cli(cmd, timeout=900)

        self.custody.log_action(
            artifact_id, "EXAMINED", self.actor,
            "Ghidra headless disassembly complete",
            nist_phase="Examination"
        )

        findings = [ForensicFinding(
            category=FindingCategory.BINARY,
            engine="ghidra",
            timestamp=datetime.now(timezone.utc).isoformat(),
            title="Binary [static analysis]",
            description="Ghidra headless analysis complete",
            raw_data={"stdout": raw[:5000]},
        )]

        # Parse script log for suspicious imports
        log_path = project_dir / "script.log"
        if log_path.exists():
            log_text = log_path.read_text(errors="ignore")
            sus_apis = [
                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                "NtUnmapViewOfSection", "WinExec", "ShellExecute",
                "URLDownloadToFile", "InternetOpen",
            ]
            for api in sus_apis:
                if api.lower() in log_text.lower():
                    findings.append(ForensicFinding(
                        category=FindingCategory.BINARY,
                        engine="ghidra",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        title=f"Binary [suspicious API: {api}]",
                        description=f"Import of {api} detected in binary",
                        raw_data={"api": api},
                        persistence_indicators=["suspicious_api_import"],
                    ))

        return findings
