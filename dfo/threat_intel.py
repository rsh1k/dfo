"""
dfo/threat_intel.py
===================
Unified Threat Intelligence layer.

Integrates:
  - IOC database (JSON files)
  - YARA rule scanning
  - MITRE ATT&CK technique lookup
  - STIX/TAXII feed ingestion (via stix2 + taxii2-client)
  - VirusTotal / AbuseIPDB / OTX lookups (optional)

Install extras:
    pip install yara-python       # YARA scanning
    pip install stix2             # STIX/TAXII
    pip install taxii2-client     # TAXII feeds
    pip install requests          # API lookups
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from dfo.models import (
    ForensicFinding, MITREMapping, YARAMatch,
    ThreatIntelConfig, FindingCategory,
)
from dfo.terminal import print_info, print_success, print_warning, print_error

logger = logging.getLogger("DFO.ThreatIntel")


# ---------------------------------------------------------------------------
# IOC Database
# ---------------------------------------------------------------------------

class IOCDatabase:
    """In-memory IOC database loaded from JSON files."""

    def __init__(self):
        self.db: dict[str, set[str]] = {
            "ip": set(), "domain": set(), "hash": set(),
            "mutex": set(), "useragent": set(),
            "email": set(), "url": set(), "registry": set(),
        }
        self._total = 0

    def load_file(self, path: Path):
        with open(path) as f:
            data = json.load(f)
        count = 0
        for key, values in data.items():
            self.db.setdefault(key, set()).update(
                v.lower().strip() for v in values
            )
            count += len(values)
        self._total += count
        print_success(
            f"Loaded [bold]{count}[/bold] IOCs from [bold]{path.name}[/bold]"
        )

    def load_directory(self, dir_path: Path):
        for f in sorted(dir_path.glob("*.json")):
            self.load_file(f)

    @property
    def total_count(self) -> int:
        return sum(len(v) for v in self.db.values())

    def check(self, text: str) -> list[str]:
        """Check a text blob against all IOCs. Returns matches."""
        text_lower = text.lower()
        matches = []
        for ioc_type, indicators in self.db.items():
            for indicator in indicators:
                if indicator in text_lower:
                    matches.append(f"{ioc_type}:{indicator}")
        return matches


# ---------------------------------------------------------------------------
# YARA Scanner
# ---------------------------------------------------------------------------

class YARAScanner:
    """Scan files or data against YARA rule sets."""

    def __init__(self):
        self._rules = []
        self._available = False
        try:
            import yara
            self._yara = yara
            self._available = True
        except ImportError:
            print_warning("yara-python not installed — YARA scanning disabled")

    @property
    def available(self) -> bool:
        return self._available

    def load_rules_directory(self, dir_path: Path):
        if not self._available:
            return
        rule_files = {}
        for f in sorted(dir_path.rglob("*.yar")):
            rule_files[f.stem] = str(f)
        for f in sorted(dir_path.rglob("*.yara")):
            rule_files[f.stem] = str(f)
        if rule_files:
            try:
                compiled = self._yara.compile(filepaths=rule_files)
                self._rules.append(compiled)
                print_success(
                    f"Loaded [bold]{len(rule_files)}[/bold] YARA rules "
                    f"from [bold]{dir_path}[/bold]"
                )
            except self._yara.Error as e:
                print_error(f"YARA compile error: {e}")

    def load_rules_file(self, path: Path):
        if not self._available:
            return
        try:
            compiled = self._yara.compile(filepath=str(path))
            self._rules.append(compiled)
            print_success(f"Loaded YARA rule: [bold]{path.name}[/bold]")
        except self._yara.Error as e:
            print_error(f"YARA compile error in {path.name}: {e}")

    def scan_file(self, filepath: Path) -> list[YARAMatch]:
        if not self._available or not self._rules:
            return []
        results = []
        for rules in self._rules:
            try:
                matches = rules.match(str(filepath))
                for m in matches:
                    results.append(YARAMatch(
                        rule_name=m.rule,
                        rule_file=m.namespace,
                        tags=list(m.tags),
                        strings_matched=[
                            str(s) for s in (m.strings or [])[:10]
                        ],
                        metadata=dict(m.meta) if m.meta else {},
                    ))
            except Exception as e:
                logger.warning("YARA scan error on %s: %s", filepath, e)
        return results

    def scan_data(self, data: bytes) -> list[YARAMatch]:
        if not self._available or not self._rules:
            return []
        results = []
        for rules in self._rules:
            try:
                matches = rules.match(data=data)
                for m in matches:
                    results.append(YARAMatch(
                        rule_name=m.rule,
                        rule_file=m.namespace,
                        tags=list(m.tags),
                        strings_matched=[
                            str(s) for s in (m.strings or [])[:10]
                        ],
                        metadata=dict(m.meta) if m.meta else {},
                    ))
            except Exception as e:
                logger.warning("YARA scan error: %s", e)
        return results


# ---------------------------------------------------------------------------
# MITRE ATT&CK Lookup
# ---------------------------------------------------------------------------

class MITREATTACKLookup:
    """
    Local MITRE ATT&CK technique database.
    Downloads ATT&CK STIX data from GitHub and provides
    keyword-based technique suggestion.
    """

    def __init__(self):
        self._techniques: list[dict] = []
        self._loaded = False

    def load(self, cache_path: Optional[Path] = None):
        """Load ATT&CK techniques from cached JSON or download."""
        if cache_path and cache_path.exists():
            self._techniques = json.loads(cache_path.read_text())
            self._loaded = True
            print_info(
                f"Loaded [bold]{len(self._techniques)}[/bold] "
                f"MITRE ATT&CK techniques from cache"
            )
            return

        try:
            import requests
            url = (
                "https://raw.githubusercontent.com/mitre-attack/"
                "attack-stix-data/master/enterprise-attack/"
                "enterprise-attack.json"
            )
            print_info("Downloading MITRE ATT&CK Enterprise data…")
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            bundle = resp.json()

            self._techniques = []
            for obj in bundle.get("objects", []):
                if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
                    refs = obj.get("external_references", [])
                    tech_id = ""
                    tech_url = ""
                    for ref in refs:
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id", "")
                            tech_url = ref.get("url", "")
                            break

                    tactics = []
                    for phase in obj.get("kill_chain_phases", []):
                        if phase.get("kill_chain_name") == "mitre-attack":
                            tactics.append(phase.get("phase_name", ""))

                    self._techniques.append({
                        "id": tech_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", "")[:500],
                        "tactics": tactics,
                        "url": tech_url,
                    })

            self._loaded = True
            print_success(
                f"Loaded [bold]{len(self._techniques)}[/bold] "
                f"MITRE ATT&CK techniques"
            )

            if cache_path:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(json.dumps(self._techniques, indent=1))

        except Exception as e:
            print_warning(f"Could not load MITRE ATT&CK: {e}")

    def suggest(self, finding: ForensicFinding,
                top_k: int = 3) -> list[MITREMapping]:
        """Keyword-based technique suggestion for a finding."""
        if not self._loaded:
            return []

        text = (
            f"{finding.title} {finding.description} "
            f"{' '.join(finding.persistence_indicators)} "
            f"{' '.join(finding.exfil_indicators)}"
        ).lower()

        scored = []
        for tech in self._techniques:
            score = 0
            name_lower = tech["name"].lower()
            desc_lower = tech["description"].lower()

            # Check keyword overlap
            for word in text.split():
                if len(word) > 3:
                    if word in name_lower:
                        score += 3
                    if word in desc_lower:
                        score += 1

            if score > 0:
                scored.append((score, tech))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            MITREMapping(
                technique_id=t["id"],
                technique_name=t["name"],
                tactic=", ".join(t["tactics"]),
                confidence=min(s / 15.0, 1.0),
                reference_url=t.get("url", ""),
            )
            for s, t in scored[:top_k]
        ]


# ---------------------------------------------------------------------------
# STIX/TAXII Feed Ingester
# ---------------------------------------------------------------------------

class STIXTAXIIIngester:
    """Ingest IOCs from STIX/TAXII feeds."""

    def __init__(self, ioc_db: IOCDatabase):
        self.ioc_db = ioc_db

    def ingest_from_taxii(self, url: str, collection_id: str):
        """Pull IOCs from a TAXII 2.0 server."""
        try:
            from stix2 import TAXIICollectionSource, Filter
            from taxii2client.v20 import Collection

            collection = Collection(
                f"{url}/stix/collections/{collection_id}/"
            )
            source = TAXIICollectionSource(collection)

            # Extract indicators
            indicators = source.query([
                Filter("type", "=", "indicator")
            ])
            count = 0
            for ind in indicators:
                pattern = ind.get("pattern", "")
                # Extract IOCs from STIX patterns
                self._parse_stix_pattern(pattern)
                count += 1

            print_success(
                f"Ingested [bold]{count}[/bold] indicators from TAXII feed"
            )
        except ImportError:
            print_warning("stix2/taxii2-client not installed")
        except Exception as e:
            print_error(f"TAXII ingestion failed: {e}")

    def ingest_stix_file(self, path: Path):
        """Load IOCs from a local STIX JSON bundle."""
        try:
            data = json.loads(path.read_text())
            objects = data.get("objects", [])
            count = 0
            for obj in objects:
                if obj.get("type") == "indicator":
                    self._parse_stix_pattern(obj.get("pattern", ""))
                    count += 1
            print_success(
                f"Loaded [bold]{count}[/bold] indicators "
                f"from [bold]{path.name}[/bold]"
            )
        except Exception as e:
            print_error(f"STIX file load failed: {e}")

    def _parse_stix_pattern(self, pattern: str):
        """Extract IOCs from STIX indicator patterns."""
        import re
        # IPv4
        for ip in re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", pattern):
            self.ioc_db.db["ip"].add(ip)
        # Domains
        for domain in re.findall(
            r"domain-name:value\s*=\s*'([^']+)'", pattern
        ):
            self.ioc_db.db["domain"].add(domain.lower())
        # Hashes (SHA-256, MD5)
        for h in re.findall(r"([a-fA-F0-9]{32,64})", pattern):
            self.ioc_db.db["hash"].add(h.lower())
        # URLs
        for url in re.findall(r"url:value\s*=\s*'([^']+)'", pattern):
            self.ioc_db.db["url"].add(url.lower())


# ---------------------------------------------------------------------------
# Unified Threat Intel Manager
# ---------------------------------------------------------------------------

class ThreatIntelManager:
    """
    Top-level manager that initializes and coordinates all
    threat intelligence sources.
    """

    def __init__(self, config: ThreatIntelConfig):
        self.config = config
        self.ioc_db = IOCDatabase()
        self.yara = YARAScanner()
        self.mitre = MITREATTACKLookup()
        self.stix = STIXTAXIIIngester(self.ioc_db)

    def initialize(self):
        """Load all configured threat intel sources."""
        # IOC files
        for ioc_path in self.config.ioc_files:
            p = Path(ioc_path)
            if p.is_dir():
                self.ioc_db.load_directory(p)
            elif p.is_file():
                self.ioc_db.load_file(p)

        # YARA rules
        for yara_dir in self.config.yara_rules_dirs:
            p = Path(yara_dir)
            if p.is_dir():
                self.yara.load_rules_directory(p)
            elif p.is_file():
                self.yara.load_rules_file(p)

        # MITRE ATT&CK
        if self.config.enable_mitre_attack:
            cache = Path("./data/mitre_attack_cache.json")
            self.mitre.load(cache_path=cache)

        # STIX/TAXII
        if self.config.stix_taxii_url and self.config.stix_taxii_collection:
            self.stix.ingest_from_taxii(
                self.config.stix_taxii_url,
                self.config.stix_taxii_collection,
            )

    def enrich_finding(self, finding: ForensicFinding):
        """Apply all threat intel enrichment to a finding."""
        # IOC check
        raw_str = json.dumps(finding.raw_data, default=str)
        finding.ioc_matches = self.ioc_db.check(raw_str)

        # MITRE mapping
        if self.config.enable_mitre_attack and self.mitre._loaded:
            finding.mitre_mappings = self.mitre.suggest(finding)

    def scan_file_yara(self, filepath: Path) -> list[YARAMatch]:
        """Run YARA scan on a file."""
        return self.yara.scan_file(filepath)
