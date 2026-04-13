"""
dfo/timeline.py
===============
Forensic Timeline Generator.

Converts findings into a chronological timeline for analysis.
Supports export to: JSONL, CSV (Timeline Explorer compatible),
and body file format (for mactime/Plaso interop).
"""

from __future__ import annotations

import csv
import json
import io
from datetime import datetime
from pathlib import Path

from dfo.models import ForensicFinding, TimelineEvent
from dfo.terminal import print_info, print_success, console


class TimelineGenerator:
    """
    Aggregates findings into a unified forensic timeline.
    """

    def __init__(self):
        self.events: list[TimelineEvent] = []

    def add_findings(self, findings: list[ForensicFinding]):
        """Convert findings into timeline events."""
        for f in findings:
            self.events.append(f.to_timeline_event())

    def add_event(self, event: TimelineEvent):
        self.events.append(event)

    def sort(self):
        """Sort events chronologically."""
        def parse_ts(ts: str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                return datetime.min
        self.events.sort(key=lambda e: parse_ts(e.timestamp))

    @property
    def count(self) -> int:
        return len(self.events)

    # --- Export methods ---

    def to_jsonl(self, path: Path):
        """Export timeline as JSONL (one event per line)."""
        self.sort()
        with open(path, "w") as f:
            for event in self.events:
                record = {
                    "timestamp": event.timestamp,
                    "source": event.source,
                    "event_type": event.event_type,
                    "description": event.description,
                    "artifact_id": event.artifact_id,
                    "mitre": [
                        {"id": m.technique_id, "name": m.technique_name}
                        for m in event.mitre_mappings
                    ] if event.mitre_mappings else [],
                }
                f.write(json.dumps(record) + "\n")
        print_success(
            f"Timeline exported: [bold]{path}[/bold] "
            f"({self.count} events)"
        )

    def to_csv(self, path: Path):
        """
        Export as CSV compatible with Timeline Explorer /
        Eric Zimmerman tools.
        """
        self.sort()
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "Source", "EventType",
                "Description", "MITRE_ID", "MITRE_Name", "ArtifactID",
            ])
            for event in self.events:
                mitre_id = ""
                mitre_name = ""
                if event.mitre_mappings:
                    mitre_id = event.mitre_mappings[0].technique_id
                    mitre_name = event.mitre_mappings[0].technique_name
                writer.writerow([
                    event.timestamp,
                    event.source,
                    event.event_type,
                    event.description[:500],
                    mitre_id,
                    mitre_name,
                    event.artifact_id,
                ])
        print_success(
            f"Timeline CSV exported: [bold]{path}[/bold] "
            f"({self.count} events)"
        )

    def display(self, max_events: int = 50):
        """Display timeline in the terminal."""
        from rich.table import Table

        self.sort()
        table = Table(
            title="[header]Forensic Timeline[/header]",
            show_header=True,
            header_style="bold bright_white on dark_blue",
            border_style="bright_cyan",
            expand=True,
        )
        table.add_column("Timestamp", width=26)
        table.add_column("Source", width=14)
        table.add_column("Type", width=12)
        table.add_column("Description", ratio=1)
        table.add_column("MITRE", width=14)

        for event in self.events[:max_events]:
            mitre = ""
            if event.mitre_mappings:
                mitre = event.mitre_mappings[0].technique_id
            table.add_row(
                event.timestamp[:26],
                event.source,
                event.event_type,
                event.description[:100],
                mitre,
            )
        console.print(table)
        if len(self.events) > max_events:
            print_info(
                f"Showing {max_events} of {len(self.events)} events. "
                f"Export for full timeline."
            )
