"""
dfo/engines/tshark.py
=====================
Network PCAP analysis via tshark (Wireshark CLI).

Fixed: proper field extraction, UDP support, structured descriptions,
       better parsing that skips decoration lines.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dfo.engines.base import BaseEngineAdapter
from dfo.models import ForensicFinding, FindingCategory


class TsharkAdapter(BaseEngineAdapter):
    """
    Wraps `tshark` for PCAP analysis.
    Uses -T fields for structured extraction instead of raw text parsing.
    """

    # ---------------------------------------------------------------
    # Profile definitions — each returns structured field output
    # ---------------------------------------------------------------

    PROFILES: dict[str, dict[str, Any]] = {
        # === Packet-level summary (covers ALL protocols) ===
        "packet_summary": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "frame.time_relative",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "ipv6.src",
                "-e", "ipv6.dst",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "frame.protocols",
                "-e", "frame.len",
                "-e", "_ws.col.Info",
                "-E", "header=y",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "occurrence=f",
            ],
            "fields": [
                "frame_number", "time_rel", "ip_src", "ip_dst",
                "ipv6_src", "ipv6_dst",
                "tcp_srcport", "tcp_dstport",
                "udp_srcport", "udp_dstport",
                "protocols", "frame_len", "info",
            ],
        },

        # === DNS queries ===
        "dns_queries": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-Y", "dns.flags.response==0",
                "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src",
                "-e", "dns.qry.name",
                "-e", "dns.qry.type",
                "-E", "header=y",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "occurrence=f",
            ],
            "fields": ["time_rel", "ip_src", "query_name", "query_type"],
        },

        # === DNS responses ===
        "dns_responses": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-Y", "dns.flags.response==1",
                "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "dns.qry.name",
                "-e", "dns.a",
                "-e", "dns.aaaa",
                "-e", "dns.resp.name",
                "-E", "header=y",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "occurrence=f",
            ],
            "fields": ["time_rel", "query_name", "resolved_a",
                        "resolved_aaaa", "resp_name"],
        },

        # === HTTP requests ===
        "http_requests": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-Y", "http.request",
                "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.request.method",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent",
                "-E", "header=y",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "occurrence=f",
            ],
            "fields": ["time_rel", "ip_src", "ip_dst", "method",
                        "host", "uri", "user_agent"],
        },

        # === TLS client hello (SNI extraction) ===
        "tls_handshakes": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-Y", "tls.handshake.type==1",
                "-T", "fields",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.dstport",
                "-e", "tls.handshake.extensions_server_name",
                "-E", "header=y",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "occurrence=f",
            ],
            "fields": ["ip_src", "ip_dst", "dst_port", "sni"],
        },

        # === Suspicious destination ports ===
        "suspicious_ports": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-Y",
                "tcp.dstport==4444 or tcp.dstport==5555 or "
                "tcp.dstport==1337 or tcp.dstport==31337 or "
                "tcp.dstport==8443 or tcp.dstport==9001 or "
                "tcp.dstport==6667 or tcp.dstport==6697 or "
                "udp.dstport==4444 or udp.dstport==5555 or "
                "udp.dstport==1337 or udp.dstport==53",
                "-T", "fields",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.dstport", "-e", "udp.dstport",
                "-e", "frame.time_relative",
                "-E", "header=y",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "occurrence=f",
            ],
            "fields": ["ip_src", "ip_dst", "tcp_dstport",
                        "udp_dstport", "time_rel"],
        },

        # === Connection endpoints summary (IP-level stats) ===
        "endpoints": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-q", "-z", "endpoints,ip",
            ],
            "fields": None,  # free-text parse
        },

        # === Protocol hierarchy ===
        "protocol_hierarchy": {
            "cmd": [
                "tshark", "-r", "{pcap}",
                "-q", "-z", "io,phs",
            ],
            "fields": None,  # free-text parse
        },
    }

    def analyze(self, evidence_path: Path, **kwargs) -> list[ForensicFinding]:
        self._check_tool("tshark")

        artifact_id = self.custody.register_artifact(
            evidence_path, self.actor,
            "PCAP file ingested for network analysis",
            nist_phase="Collection"
        )
        findings: list[ForensicFinding] = []

        for profile_name, profile in self.PROFILES.items():
            cmd = [c.replace("{pcap}", str(evidence_path))
                   for c in profile["cmd"]]
            raw = self._run_cli(cmd)
            self.custody.log_action(
                artifact_id, "EXAMINED", self.actor,
                f"Ran tshark profile '{profile_name}'",
                nist_phase="Examination"
            )

            if profile["fields"] is not None:
                # Structured field output
                findings.extend(
                    self._parse_fields(profile_name, profile["fields"], raw)
                )
            else:
                # Free-text stat output (endpoints, protocol hierarchy)
                findings.extend(
                    self._parse_stats(profile_name, raw)
                )

        return findings

    # ---------------------------------------------------------------
    # Structured field parser (TSV/pipe-delimited with header)
    # ---------------------------------------------------------------

    def _parse_fields(self, profile: str, field_names: list[str],
                      raw: str) -> list[ForensicFinding]:
        results = []
        lines = raw.strip().splitlines()
        if len(lines) < 2:
            return results  # header only or empty

        # Skip the header row (first line)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            parts = [p.strip().strip('"') for p in line.split("|")]

            # Build a dict from field_names + parts
            record: dict[str, str] = {}
            for i, name in enumerate(field_names):
                record[name] = parts[i] if i < len(parts) else ""

            # Resolve source/dest IP (prefer IPv4, fall back to IPv6)
            src_ip = (record.get("ip_src") or record.get("ipv6_src")
                      or "unknown")
            dst_ip = (record.get("ip_dst") or record.get("ipv6_dst")
                      or "unknown")

            # Build a human-readable description with actual data
            description = self._build_description(profile, record,
                                                   src_ip, dst_ip)

            finding = ForensicFinding(
                category=FindingCategory.NETWORK,
                engine="tshark",
                timestamp=datetime.now(timezone.utc).isoformat(),
                title=f"Network [{profile}]",
                description=description,
                raw_data={
                    "profile": profile,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    **record,
                },
            )

            # --- Heuristic flags ---

            # Suspicious ports
            if profile == "suspicious_ports":
                port = record.get("tcp_dstport") or record.get("udp_dstport")
                finding.exfil_indicators.append(
                    f"suspicious_port:{port}"
                )

            # DGA detection on DNS queries
            if profile == "dns_queries":
                domain = record.get("query_name", "")
                if self._looks_like_dga(domain):
                    finding.persistence_indicators.append(
                        "possible_dga_domain"
                    )

            # Suspicious user agents
            if profile == "http_requests":
                ua = record.get("user_agent", "").lower()
                if any(s in ua for s in [
                    "python-urllib", "wget", "curl", "powershell",
                    "certutil", "loader", "bot",
                ]):
                    finding.exfil_indicators.append(
                        f"suspicious_user_agent:{record.get('user_agent', '')}"
                    )

            results.append(finding)

        return results

    # ---------------------------------------------------------------
    # Free-text stats parser (for -z endpoints, -z io,phs etc.)
    # ---------------------------------------------------------------

    def _parse_stats(self, profile: str, raw: str) -> list[ForensicFinding]:
        results = []
        in_data = False

        for line in raw.strip().splitlines():
            stripped = line.strip()

            # Skip decoration lines
            if not stripped or stripped.startswith("=") or stripped.startswith("-"):
                in_data = True  # next non-decoration line is data
                continue

            # Skip known header labels
            if any(stripped.lower().startswith(h) for h in [
                "filter:", "ipv4 endpoints", "protocol",
                "| address", "|   address",
            ]):
                continue

            # Parse endpoint lines: "IP_ADDR  packets  bytes ..."
            if profile == "endpoints":
                parts = stripped.split()
                if parts and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ip = parts[0]
                    packets = parts[1] if len(parts) > 1 else "?"
                    tx_bytes = parts[2] if len(parts) > 2 else "?"
                    rx_packets = parts[3] if len(parts) > 3 else "?"
                    rx_bytes = parts[4] if len(parts) > 4 else "?"
                    description = (
                        f"Endpoint {ip}: "
                        f"TX {packets} pkts / {tx_bytes} bytes, "
                        f"RX {rx_packets} pkts / {rx_bytes} bytes"
                    )
                    results.append(ForensicFinding(
                        category=FindingCategory.NETWORK,
                        engine="tshark",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        title=f"Network [{profile}]",
                        description=description,
                        raw_data={
                            "profile": profile,
                            "ip": ip,
                            "packets": packets,
                            "bytes": tx_bytes,
                        },
                    ))
                continue

            # Parse protocol hierarchy lines
            if profile == "protocol_hierarchy":
                match = re.match(
                    r"^\s*([\w:\.]+)\s+frames:(\d+)\s+bytes:(\d+)", stripped
                )
                if match:
                    proto, frames, nbytes = match.groups()
                    description = (
                        f"Protocol {proto}: {frames} frames, {nbytes} bytes"
                    )
                    results.append(ForensicFinding(
                        category=FindingCategory.NETWORK,
                        engine="tshark",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        title=f"Network [{profile}]",
                        description=description,
                        raw_data={
                            "profile": profile,
                            "protocol": proto,
                            "frames": frames,
                            "bytes": nbytes,
                        },
                    ))

        return results

    # ---------------------------------------------------------------
    # Human-readable descriptions per profile
    # ---------------------------------------------------------------

    def _build_description(self, profile: str, record: dict,
                           src_ip: str, dst_ip: str) -> str:
        if profile == "packet_summary":
            src_port = record.get("tcp_srcport") or record.get("udp_srcport") or ""
            dst_port = record.get("tcp_dstport") or record.get("udp_dstport") or ""
            protocols = record.get("protocols", "")
            info = record.get("info", "")
            frame_len = record.get("frame_len", "")
            src = f"{src_ip}:{src_port}" if src_port else src_ip
            dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
            return (
                f"Packet #{record.get('frame_number', '?')}: "
                f"{src} → {dst} | {protocols} | "
                f"{frame_len} bytes | {info}"
            )

        elif profile == "dns_queries":
            return (
                f"DNS query from {src_ip}: "
                f"{record.get('query_name', '?')} "
                f"(type={record.get('query_type', '?')})"
            )

        elif profile == "dns_responses":
            resolved = (record.get("resolved_a") or
                        record.get("resolved_aaaa") or "no-answer")
            return (
                f"DNS response: {record.get('query_name', '?')} → {resolved}"
            )

        elif profile == "http_requests":
            return (
                f"HTTP {record.get('method', '?')} "
                f"{src_ip} → {dst_ip} "
                f"Host={record.get('host', '?')} "
                f"URI={record.get('uri', '?')} "
                f"UA={record.get('user_agent', '?')}"
            )

        elif profile == "tls_handshakes":
            return (
                f"TLS ClientHello {src_ip} → {dst_ip}:{record.get('dst_port', '?')} "
                f"SNI={record.get('sni', 'none')}"
            )

        elif profile == "suspicious_ports":
            port = record.get("tcp_dstport") or record.get("udp_dstport") or "?"
            return (
                f"Suspicious connection {src_ip} → {dst_ip}:{port}"
            )

        return f"{src_ip} → {dst_ip} | {record}"

    # ---------------------------------------------------------------
    # DGA heuristic
    # ---------------------------------------------------------------

    @staticmethod
    def _looks_like_dga(domain: str) -> bool:
        """Heuristic: long random-looking subdomains suggest DGA."""
        if not domain:
            return False
        labels = domain.split(".")
        if labels and len(labels[0]) > 15:
            consonants = sum(1 for c in labels[0].lower()
                             if c in "bcdfghjklmnpqrstvwxyz")
            ratio = consonants / max(len(labels[0]), 1)
            return ratio > 0.7
        return False
