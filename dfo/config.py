"""
dfo/config.py
=============
Configuration management — load/save DFO settings from JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import asdict

from dfo.models import DFOConfig


def load_config(path: Path = Path("dfo.json")) -> DFOConfig:
    """Load config from a JSON file, falling back to defaults."""
    if path.exists():
        data = json.loads(path.read_text())
        return DFOConfig(**data)
    return DFOConfig()


def save_config(config: DFOConfig, path: Path = Path("dfo.json")):
    """Persist config to JSON."""
    path.write_text(json.dumps(asdict(config), indent=2))
