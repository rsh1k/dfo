"""
dfo/engines/base.py
===================
Abstract base class for all forensic engine adapters.
"""

from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from dfo.custody import ChainOfCustody
from dfo.models import ForensicFinding
from dfo.terminal import console, print_info, print_error


class BaseEngineAdapter(ABC):
    """
    Each adapter wraps one forensic tool's CLI, runs it against an
    evidence file, and returns normalized ForensicFinding objects.
    """

    def __init__(self, custody: ChainOfCustody, actor: str = "system"):
        self.custody = custody
        self.actor = actor
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def analyze(self, evidence_path: Path, **kwargs) -> list[ForensicFinding]:
        """Run the engine on the evidence and return findings."""
        ...

    def _run_cli(self, cmd: list[str], timeout: int = 300) -> str:
        """Execute a CLI tool and return stdout."""
        self.logger.info("Executing: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0:
                self.logger.warning("Exit code %d: %s",
                                    result.returncode, result.stderr[:300])
            return result.stdout
        except FileNotFoundError:
            msg = f"Tool not found: {cmd[0]}. Is it installed and on PATH?"
            print_error(msg)
            raise RuntimeError(msg)
        except subprocess.TimeoutExpired:
            msg = f"Tool timed out after {timeout}s: {cmd[0]}"
            print_error(msg)
            raise RuntimeError(msg)

    def _check_tool(self, tool_name: str) -> bool:
        """Check if an external tool is available on PATH."""
        import shutil
        found = shutil.which(tool_name) is not None
        if not found:
            self.logger.warning("%s not found on PATH", tool_name)
        return found
