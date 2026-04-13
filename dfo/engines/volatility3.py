"""
dfo/engines/volatility3.py
==========================
Memory dump analysis via Volatility 3.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from dfo.engines.base import BaseEngineAdapter
from dfo.models import ForensicFinding, FindingCategory


class Volatility3Adapter(BaseEngineAdapter):
    """
    Wraps Volatility 3 for RAM dump analysis.
    Runs configurable plugin suites and normalizes JSON output.
    """

    DEFAULT_PLUGINS = [
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind",
        "windows.registry.hivelist.HiveList",
        "windows.cmdline.CmdLine",
        "windows.dlllist.DllList",
    ]

    SUSPICIOUS_PROCS = {
        "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
        "smss.exe", "wininit.exe", "winlogon.exe",
    }

    def analyze(self, evidence_path: Path, **kwargs) -> list[ForensicFinding]:
        self._check_tool("vol")

        plugins = kwargs.get("plugins", self.DEFAULT_PLUGINS)
        artifact_id = self.custody.register_artifact(
            evidence_path, self.actor,
            "Memory dump ingested for volatile analysis",
            nist_phase="Collection"
        )
        findings: list[ForensicFinding] = []

        for plugin in plugins:
            cmd = ["vol", "-f", str(evidence_path), "-r", "json", plugin]
            raw = self._run_cli(cmd, timeout=600)
            self.custody.log_action(
                artifact_id, "EXAMINED", self.actor,
                f"Ran Volatility plugin '{plugin}'",
                nist_phase="Examination"
            )
            findings.extend(self._parse(plugin, raw))

        return findings

    def _parse(self, plugin: str, raw: str) -> list[ForensicFinding]:
        results = []
        try:
            rows = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            rows = [{"raw_line": l} for l in raw.splitlines() if l.strip()]

        plugin_short = plugin.split(".")[-1]

        for row in rows:
            finding = ForensicFinding(
                category=FindingCategory.MEMORY,
                engine="volatility3",
                timestamp=datetime.now(timezone.utc).isoformat(),
                title=f"Memory [{plugin_short}]",
                description=str(row)[:200],
                raw_data={"plugin": plugin, "record": row},
            )

            if "malfind" in plugin.lower():
                finding.persistence_indicators.append("injected_code_detected")

            if "pstree" in plugin.lower() or "pslist" in plugin.lower():
                proc_name = str(row.get("ImageFileName", "")).lower()
                ppid = row.get("PPID", 0)
                if proc_name == "svchost.exe" and ppid not in (0,):
                    finding.persistence_indicators.append(
                        "unusual_parent_process"
                    )

            if "netscan" in plugin.lower():
                state = str(row.get("State", "")).upper()
                if state == "ESTABLISHED":
                    finding.exfil_indicators.append("active_network_connection")

            results.append(finding)
        return results
