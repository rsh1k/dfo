"""
DFO v2.0 — Enterprise AI-Powered Digital Forensics Platform
=============================================================
Core models, configuration, and shared types.

Enterprise features:
  - Multi-LLM support (OpenAI, Anthropic, Ollama, HuggingFace)
  - MITRE ATT&CK mapping
  - YARA rule scanning
  - STIX/TAXII threat intel feeds
  - Timeline generation (Plaso/log2timeline, CSV, JSONL)
  - Cloud forensics (AWS CloudTrail, Azure, GCP)
  - Sigma rule detection
  - AI-driven automated analysis
  - Multi-format evidence support
  - Case management system

File: dfo/models.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingCategory(Enum):
    NETWORK = "network"
    MEMORY = "memory"
    BINARY = "binary"
    DISK = "disk"
    LOG = "log"
    CLOUD = "cloud"
    EMAIL = "email"
    REGISTRY = "registry"
    BROWSER = "browser"
    MOBILE = "mobile"


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
    INFO = "INFO"

    @classmethod
    def from_score(cls, score: float) -> SeverityTier:
        if score >= 0.8: return cls.CRITICAL
        if score >= 0.6: return cls.HIGH
        if score >= 0.3: return cls.MEDIUM
        if score >= 0.1: return cls.LOW
        return cls.INFO


class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    NONE = "none"


class EvidenceFormat(Enum):
    """All supported evidence formats."""
    # Network
    PCAP = "pcap"
    PCAPNG = "pcapng"
    NETFLOW = "netflow"
    ZEEK_LOG = "zeek_log"
    # Memory
    RAW_MEMORY = "raw_memory"
    VMEM = "vmem"
    DMP = "dmp"
    LIME = "lime"
    # Disk
    E01 = "e01"
    EX01 = "ex01"
    DD = "dd"
    RAW_DISK = "raw_disk"
    VMDK = "vmdk"
    VHD = "vhd"
    QCOW2 = "qcow2"
    # Binary
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    # Log
    EVTX = "evtx"
    SYSLOG = "syslog"
    JSON_LOG = "json_log"
    CSV_LOG = "csv_log"
    # Cloud
    CLOUDTRAIL = "cloudtrail"
    AZURE_ACTIVITY = "azure_activity"
    GCP_AUDIT = "gcp_audit"
    # Email
    PST = "pst"
    MBOX = "mbox"
    EML = "eml"
    # Browser
    SQLITE_BROWSER = "sqlite_browser"
    # Mobile
    ANDROID_BACKUP = "android_backup"
    IOS_BACKUP = "ios_backup"
    # Generic
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------

@dataclass
class MITREMapping:
    """MITRE ATT&CK technique mapping."""
    technique_id: str = ""          # e.g. "T1059.001"
    technique_name: str = ""        # e.g. "PowerShell"
    tactic: str = ""                # e.g. "Execution"
    confidence: float = 0.0         # 0.0–1.0
    reference_url: str = ""


@dataclass
class YARAMatch:
    """Result from a YARA rule scan."""
    rule_name: str = ""
    rule_file: str = ""
    tags: list[str] = field(default_factory=list)
    strings_matched: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class TimelineEvent:
    """A single event in the forensic timeline."""
    timestamp: str = ""
    source: str = ""                # engine/file that produced it
    event_type: str = ""            # e.g. "file_modified", "process_created"
    description: str = ""
    artifact_id: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    mitre_mappings: list[MITREMapping] = field(default_factory=list)


@dataclass
class ForensicFinding:
    """Normalized artifact record produced by any engine adapter."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: FindingCategory = FindingCategory.NETWORK
    engine: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    title: str = ""
    description: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    # Threat indicators
    ioc_matches: list[str] = field(default_factory=list)
    persistence_indicators: list[str] = field(default_factory=list)
    exfil_indicators: list[str] = field(default_factory=list)
    # MITRE ATT&CK
    mitre_mappings: list[MITREMapping] = field(default_factory=list)
    # YARA
    yara_matches: list[YARAMatch] = field(default_factory=list)
    # Scoring
    severity_score: float = 0.0
    # AI analysis
    ai_summary: str = ""
    ai_recommendation: str = ""

    @property
    def severity(self) -> SeverityTier:
        return SeverityTier.from_score(self.severity_score)

    def to_timeline_event(self) -> TimelineEvent:
        return TimelineEvent(
            timestamp=self.timestamp,
            source=self.engine,
            event_type=self.category.value,
            description=self.description,
            artifact_id=self.id,
            raw_data=self.raw_data,
            mitre_mappings=self.mitre_mappings,
        )


@dataclass
class CustodyEntry:
    """Single entry in the chain-of-custody log."""
    timestamp: str = ""
    action: str = ""
    actor: str = ""
    artifact_id: str = ""
    sha256_hash: str = ""
    md5_hash: str = ""
    description: str = ""
    nist_phase: str = ""
    file_size: int = 0
    file_name: str = ""


@dataclass
class CaseInfo:
    """Case metadata for the case management system."""
    case_id: str = ""
    case_name: str = ""
    analyst: str = ""
    organization: str = ""
    classification: str = "TLP:AMBER"  # TLP marking
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = ""
    status: str = "OPEN"   # OPEN, IN_PROGRESS, CLOSED, ARCHIVED
    description: str = ""
    tags: list[str] = field(default_factory=list)
    evidence_files: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: LLMProvider = LLMProvider.NONE
    model: str = ""
    api_key: str = ""                    # or env var name
    api_base: str = ""                   # for Ollama / custom endpoints
    temperature: float = 0.1
    max_tokens: int = 4096

    @classmethod
    def ollama(cls, model: str = "llama3.1:8b",
               base: str = "http://localhost:11434") -> LLMConfig:
        return cls(
            provider=LLMProvider.OLLAMA,
            model=model,
            api_base=base,
        )

    @classmethod
    def openai(cls, model: str = "gpt-4o",
               api_key: str = "OPENAI_API_KEY") -> LLMConfig:
        return cls(
            provider=LLMProvider.OPENAI,
            model=model,
            api_key=api_key,
        )

    @classmethod
    def anthropic(cls, model: str = "claude-sonnet-4-20250514",
                  api_key: str = "ANTHROPIC_API_KEY") -> LLMConfig:
        return cls(
            provider=LLMProvider.ANTHROPIC,
            model=model,
            api_key=api_key,
        )

    @classmethod
    def huggingface(cls, model: str = "mistralai/Mistral-7B-Instruct-v0.3",
                    api_key: str = "HF_TOKEN") -> LLMConfig:
        return cls(
            provider=LLMProvider.HUGGINGFACE,
            model=model,
            api_key=api_key,
        )


@dataclass
class ThreatIntelConfig:
    """Threat intelligence source configuration."""
    ioc_files: list[str] = field(default_factory=list)
    yara_rules_dirs: list[str] = field(default_factory=list)
    stix_taxii_url: str = ""
    stix_taxii_collection: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    abuse_ipdb_key: str = ""
    virustotal_key: str = ""
    otx_key: str = ""
    enable_mitre_attack: bool = True


@dataclass
class DFOConfig:
    """Master configuration for the DFO platform."""
    case_id: str = "UNSET"
    analyst: str = "auto"
    organization: str = ""
    log_dir: str = "./cases"
    # LLM
    llm: LLMConfig = field(default_factory=LLMConfig)
    # Threat Intel
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    # NLI / RAG
    chroma_dir: str = "./chroma_db"
    embedding_model: str = "all-MiniLM-L6-v2"
    # Scorer weights (NIST SP 800-61)
    scorer_weights: dict[str, float] = field(default_factory=lambda: {
        "ioc": 0.25,
        "persistence": 0.20,
        "exfiltration": 0.20,
        "yara": 0.15,
        "mitre": 0.10,
        "ai_risk": 0.10,
    })
    # Timeline
    enable_timeline: bool = True
    timeline_format: str = "jsonl"      # jsonl, csv, or plaso
    # Automation
    auto_score: bool = True
    auto_ai_analyze: bool = False       # requires LLM config
    auto_yara_scan: bool = True
    auto_mitre_map: bool = True
    # Export
    report_format: str = "markdown"     # markdown, html, pdf, json
