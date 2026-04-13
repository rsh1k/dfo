"""
dfo/engines/tshark.py
=====================
Network PCAP analysis via tshark (Wireshark CLI).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dfo.engines.base import BaseEngineAdapter
from dfo.models import ForensicFinding, FindingCategory


class TsharkAdapter(BaseEngineAdapter):
    """
    Wraps `tshark` for PCAP analysis.
    Runs multiple analysis profiles and normalizes output.
    """

    PROFILES = {
        "conversations": [
            "tshark", "-r", "{pcap}", "-q", "-z", "conv,tcp"
        ],
        "dns_queries": [
            "tshark", "-r", "{pcap}", "-Y", "dns.flags.response==0",
            "-T", "fields",
            "-e", "frame.time", "-e", "ip.src",
            "-e", "dns.qry.name", "-e", "dns.qry.type",
            "-E", "separator=|"
        ],
        "http_requests": [
            "tshark", "-r", "{pcap}", "-Y", "http.request",
            "-T", "fields",
            "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
            "-e", "http.host", "-e", "http.request.uri",
            "-e", "http.request.method",
            "-E", "separator=|"
        ],
        "tls_handshakes": [
            "tshark", "-r", "{pcap}", "-Y", "tls.handshake.type==1",
            "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tls.handshake.extensions_server_name",
            "-E", "separator=|"
        ],
        "suspicious_ports": [
            "tshark", "-r", "{pcap}", "-Y",
            "tcp.dstport==4444 or tcp.dstport==5555 or "
            "tcp.dstport==1337 or tcp.dstport==31337 or "
            "tcp.dstport==8443 or tcp.dstport==9001",
            "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.dstport", "-e", "frame.time",
            "-E", "separator=|"
        ],
    }

    def analyze(self, evidence_path: Path, **kwargs) -> list[ForensicFinding]:
        self._check_tool("tshark")

        artifact_id = self.custody.register_artifact(
            evidence_path, self.actor,
            "PCAP file ingested for network analysis",
            nist_phase="Collection"
        )
        findings: list[ForensicFinding] = []

        for profile_name, cmd_template in self.PROFILES.items():
            cmd = [c.replace("{pcap}", str(evidence_path)) for c in cmd_template]
            raw = self._run_cli(cmd)
            self.custody.log_action(
                artifact_id, "EXAMINED", self.actor,
                f"Ran tshark profile '{profile_name}'",
                nist_phase="Examination"
            )
            findings.extend(self._parse(profile_name, raw))

        return findings

    def _parse(self, profile: str, raw: str) -> list[ForensicFinding]:
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("-"):
                continue

            finding = ForensicFinding(
                category=FindingCategory.NETWORK,
                engine="tshark",
                timestamp=datetime.now(timezone.utc).isoformat(),
                title=f"Network [{profile}]",
                description=line,
                raw_data={"profile": profile, "line": line},
            )

            if profile == "suspicious_ports":
                finding.exfil_indicators.append("suspicious_port_connection")

            if profile == "dns_queries":
                parts = line.split("|")
                if len(parts) >= 3:
                    domain = parts[2].strip()
                    if self._looks_like_dga(domain):
                        finding.persistence_indicators.append("possible_dga_domain")

            results.append(finding)
        return results

    @staticmethod
    def _looks_like_dga(domain: str) -> bool:
        """Heuristic: long random-looking subdomains suggest DGA."""
        labels = domain.split(".")
        if labels and len(labels[0]) > 15:
            consonants = sum(1 for c in labels[0].lower()
                             if c in "bcdfghjklmnpqrstvwxyz")
            ratio = consonants / max(len(labels[0]), 1)
            return ratio > 0.7
        return False
