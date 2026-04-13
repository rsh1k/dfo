"""
dfo/orchestrator.py
===================
Main orchestrator class — ties engines, scoring, NLI,
custody, and state persistence together.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from dfo.models import ForensicFinding, FindingCategory
from dfo.custody import ChainOfCustody
from dfo.scorer import ArtifactScorer
from dfo.report import ReportGenerator


class ForensicsOrchestrator:
    """
    Top-level controller.

    Usage:
        orch = ForensicsOrchestrator(case_id="IR-2026-0042")
        orch.ingest(Path("capture.pcap"), engine="tshark")
        orch.score_all()
        result = orch.ask("Show suspicious outbound connections")
        report = orch.generate_report()
    """

    _ENGINE_CLASSES: dict[str, str] = {
        "tshark":      "dfo.engines.tshark.TsharkAdapter",
        "volatility3": "dfo.engines.volatility3.Volatility3Adapter",
        "ghidra":      "dfo.engines.ghidra.GhidraAdapter",
        "sleuthkit":   "dfo.engines.sleuthkit.SleuthKitAdapter",
    }

    def __init__(self, case_id: str, log_dir: Path = Path("./cases"),
                 analyst: str = "auto"):
        self.case_id = case_id
        self.analyst = analyst
        self.case_dir = log_dir / case_id
        self.case_dir.mkdir(parents=True, exist_ok=True)

        self.custody = ChainOfCustody(case_id, self.case_dir)
        self.scorer = ArtifactScorer()
        self.findings: list[ForensicFinding] = []
        self.nli = None
        self.report_gen = ReportGenerator()
        self.logger = logging.getLogger("DFO.Orchestrator")

    # --- Engine loading ---

    def _load_engine(self, engine: str):
        """Dynamically import an engine adapter class."""
        if engine not in self._ENGINE_CLASSES:
            raise ValueError(
                f"Unknown engine '{engine}'. "
                f"Available: {list(self._ENGINE_CLASSES.keys())}"
            )
        module_path, class_name = self._ENGINE_CLASSES[engine].rsplit(".", 1)
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)

    # --- Evidence ingestion ---

    def ingest(self, evidence_path: Path, engine: str,
               **kwargs) -> list[ForensicFinding]:
        adapter_cls = self._load_engine(engine)
        adapter = adapter_cls(self.custody, self.analyst)
        new_findings = adapter.analyze(evidence_path, **kwargs)
        self.findings.extend(new_findings)
        self.logger.info("Engine '%s' → %d findings", engine, len(new_findings))
        return new_findings

    # --- IOC loading ---

    def load_iocs(self, ioc_path: Path):
        self.scorer.load_iocs_from_file(ioc_path)

    # --- Scoring ---

    def score_all(self) -> list[ForensicFinding]:
        self.findings = self.scorer.score_all(self.findings)
        return self.findings

    # --- NLI ---

    def build_index(self):
        from dfo.nli import NaturalLanguageInterface
        self.nli = NaturalLanguageInterface(
            collection_name=f"case_{self.case_id}"
        )
        self.nli.index_findings(self.findings)

    def ask(self, question: str, top_k: int = 10) -> dict:
        if self.nli is None:
            self.build_index()
        return self.nli.query(question, top_k=top_k)

    # --- Reporting ---

    def generate_report(self) -> str:
        return self.report_gen.generate_markdown(
            self.case_id, self.findings, self.custody, self.analyst
        )

    # --- State persistence ---

    def save_state(self):
        """Serialize findings to JSON so they persist between CLI calls."""
        state_path = self.case_dir / "findings.json"
        data = []
        for f in self.findings:
            d = {
                "id": f.id,
                "category": f.category.value,
                "engine": f.engine,
                "timestamp": f.timestamp,
                "title": f.title,
                "description": f.description,
                "raw_data": f.raw_data,
                "ioc_matches": f.ioc_matches,
                "persistence_indicators": f.persistence_indicators,
                "exfil_indicators": f.exfil_indicators,
                "severity_score": f.severity_score,
            }
            data.append(d)
        state_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_state(self):
        """Reload findings from a previous session."""
        state_path = self.case_dir / "findings.json"
        if not state_path.exists():
            raise FileNotFoundError(f"No saved state at {state_path}")

        data = json.loads(state_path.read_text(encoding="utf-8"))
        self.findings = []
        for d in data:
            f = ForensicFinding(
                id=d["id"],
                category=FindingCategory(d["category"]),
                engine=d["engine"],
                timestamp=d["timestamp"],
                title=d["title"],
                description=d["description"],
                raw_data=d["raw_data"],
                ioc_matches=d.get("ioc_matches", []),
                persistence_indicators=d.get("persistence_indicators", []),
                exfil_indicators=d.get("exfil_indicators", []),
                severity_score=d.get("severity_score", 0.0),
            )
            self.findings.append(f)
        self.logger.info("Loaded %d findings from state", len(self.findings))
