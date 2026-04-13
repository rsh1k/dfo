<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/NIST-SP%20800--86-FF6B35?style=for-the-badge" />
  <img src="https://img.shields.io/badge/NIST-SP%20800--61r2-FF6B35?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-22C55E?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Rich-CLI-00D4AA?style=for-the-badge&logo=gnometerminal&logoColor=white" />
  <img src="https://img.shields.io/badge/LangChain-RAG-1C3C3C?style=for-the-badge" />
</p>

<h1 align="center">🔬 Digital Forensics Orchestrator (DFO)</h1>

<p align="center">
  <b>A modular, NIST-compliant DFIR framework that unifies open-source forensic engines<br>behind a colorized CLI with natural language querying.</b>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#%EF%B8%8F-architecture">Architecture</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-nist-compliance">NIST Compliance</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## 🎯 What is DFO?

DFO is a **post-incident digital forensics framework** designed for blue-team analysts and DFIR professionals. It wraps industry-standard open-source forensic tools (Wireshark, Volatility, Ghidra, SleuthKit) into a single unified interface with:

- **One CLI to rule them all** — Ingest PCAPs, memory dumps, binaries, and disk images through the same command
- **Automatic severity scoring** — Findings ranked by IOC matches, persistence indicators, and exfiltration signals using NIST SP 800-61 Rev. 2 weights
- **Natural language queries** — Ask questions in English like *"Find suspicious outbound connections from the memory dump"* using RAG-powered semantic search
- **Full chain of custody** — Every artifact hashed, timestamped, and logged per NIST SP 800-86
- **Beautiful terminal output** — Color-coded severity tiers, progress bars, interactive tables, and tree views

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/rsh1k/dfo.git
cd dfo

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows

# Install DFO with all optional dependencies
pip install -e ".[all]"

# Verify the installation
dfo --help
```

### Minimal Install (no NLI / RAG)

If you only need the forensic engines and scoring without the natural language query layer:

```bash
pip install -e .
```

### First Run

```bash
# Launch an interactive forensic session
dfo interactive --case IR-2026-0042 --analyst "J. Smith"

# Or run individual commands
dfo ingest -c IR-2026-0042 -e tshark -f evidence/traffic.pcap
dfo score  -c IR-2026-0042 -i threat_intel/iocs.json
dfo ask    -c IR-2026-0042 "Show all DNS queries to suspicious domains"
dfo report -c IR-2026-0042 -o report.md
```

---

## ✨ Features

### 🔌 Multi-Engine Integration

| Engine | Tool | Evidence Type | What It Extracts |
|--------|------|---------------|------------------|
| **tshark** | Wireshark CLI | `.pcap` / `.pcapng` | TCP conversations, DNS queries, HTTP requests, TLS handshakes, suspicious port connections |
| **volatility3** | Volatility 3 | `.raw` / `.vmem` / `.dmp` | Process lists, network connections, injected code (malfind), registry hives, command lines, DLL lists |
| **ghidra** | Ghidra Headless | `.exe` / `.dll` / `.bin` | Function exports, suspicious API imports (VirtualAlloc, CreateRemoteThread, etc.), string analysis |
| **sleuthkit** | SleuthKit | `.E01` / `.dd` / `.raw` | Partition tables, recursive file listings, deleted file recovery, suspicious file extensions |

### 🎯 NIST SP 800-61 Artifact Scoring

Every finding is scored on a **0.0 – 1.0 scale** using configurable weights:

```
Total Score = (0.40 × IOC Match) + (0.30 × Persistence) + (0.30 × Exfiltration)
```

| Component | Weight | What It Detects |
|-----------|--------|-----------------|
| **IOC Match** | 40% | Cross-references findings against your threat intel database (IPs, domains, hashes, mutexes, user-agents) |
| **Persistence** | 30% | Injected code, unusual parent processes, DGA domains, deleted files, suspicious API imports, registry artifacts |
| **Exfiltration** | 30% | Suspicious port connections (4444, 1337, 31337...), active outbound network connections, staging archives |

### 🧠 Natural Language Interface (RAG)

Built on **LangChain + ChromaDB + HuggingFace Embeddings**, the NLI lets you query your forensic database in plain English:

```bash
dfo ask -c IR-2026-0042 "Find all suspicious outbound connections from memory"
dfo ask -c IR-2026-0042 "Which processes have injected code?"
dfo ask -c IR-2026-0042 "Show deleted files with suspicious extensions"
dfo ask -c IR-2026-0042 "List all DNS queries to known C2 domains"
```

Results are ranked by both **semantic relevance** and **severity score**, displayed in color-coded panels.

### 🎨 Colorized Terminal Output

DFO uses **Rich** for a professional terminal experience:

| Severity | Color | Score Range | Icon |
|----------|-------|-------------|------|
| CRITICAL | 🟥 Bold Red | ≥ 0.8 | 🔴 |
| HIGH | 🟧 Orange | ≥ 0.6 | 🟠 |
| MEDIUM | 🟨 Yellow | ≥ 0.3 | 🟡 |
| LOW | 🟩 Green | < 0.3 | 🟢 |

Each forensic engine also has its own color for instant visual identification:
- **tshark** → 🔵 Bright Blue
- **volatility3** → 🟣 Bright Magenta
- **ghidra** → 🔴 Bright Red
- **sleuthkit** → 🟡 Bright Yellow

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer (Click + Rich)              │
│         dfo ingest │ score │ ask │ report │ status       │
├─────────────────────────────────────────────────────────┤
│                  ForensicsOrchestrator                   │
│          (State persistence, engine dispatch)            │
├───────────┬───────────┬──────────┬──────────────────────┤
│  Tshark   │ Vol3      │  Ghidra  │  SleuthKit           │
│  Adapter  │ Adapter   │  Adapter │  Adapter             │
├───────────┴───────────┴──────────┴──────────────────────┤
│              ForensicFinding (Unified Model)             │
├─────────────────────┬───────────────────────────────────┤
│   ArtifactScorer    │   NaturalLanguageInterface        │
│   (NIST 800-61)     │   (LangChain + ChromaDB)          │
├─────────────────────┴───────────────────────────────────┤
│  ChainOfCustody (NIST 800-86)  │  ReportGenerator       │
└─────────────────────────────────────────────────────────┘
```

### Project Structure

```
dfo/
├── README.md                   # You are here
├── setup.py                    # Package installer with extras
├── requirements.txt            # Flat dependency list
├── dfo/
│   ├── __init__.py             # Package version
│   ├── cli.py                  # Click CLI with 6 commands + interactive mode
│   ├── orchestrator.py         # Main controller with state persistence
│   ├── models.py               # ForensicFinding, CustodyEntry, enums
│   ├── terminal.py             # Rich color theme, tables, panels, progress bars
│   ├── custody.py              # Chain of Custody (NIST SP 800-86)
│   ├── scorer.py               # Weighted artifact scorer (NIST SP 800-61)
│   ├── nli.py                  # RAG layer (LangChain + ChromaDB)
│   ├── report.py               # Markdown report generator
│   ├── config.py               # JSON configuration management
│   ├── engines/
│   │   ├── __init__.py         # Engine registry
│   │   ├── base.py             # Abstract base adapter (Strategy Pattern)
│   │   ├── tshark.py           # Network PCAP analysis
│   │   ├── volatility3.py      # Memory dump analysis
│   │   ├── ghidra.py           # Binary static analysis
│   │   └── sleuthkit.py        # Disk / filesystem forensics
│   └── data/
│       └── sample_iocs.json    # Example IOC database
├── tests/                      # Unit tests
├── cases/                      # Auto-created case directories
└── docs/                       # Additional documentation
```

---

## 📖 Usage

### CLI Commands

#### `dfo ingest` — Ingest Evidence

Run a forensic engine against an evidence file:

```bash
dfo ingest --case IR-2026-0042 \
           --engine tshark \
           --file evidence/capture.pcap \
           --analyst "J. Smith"

dfo ingest -c IR-2026-0042 -e volatility3 -f evidence/memdump.raw
dfo ingest -c IR-2026-0042 -e ghidra -f evidence/malware.exe
dfo ingest -c IR-2026-0042 -e sleuthkit -f evidence/disk.E01 --offset 2048
```

#### `dfo score` — Score & Rank Findings

Apply NIST SP 800-61 weighted scoring with optional IOC matching:

```bash
dfo score --case IR-2026-0042 --iocs threat_intel/iocs.json --top 30
```

#### `dfo ask` — Natural Language Query

Query findings using plain English:

```bash
dfo ask -c IR-2026-0042 "What processes have injected code?"
dfo ask -c IR-2026-0042 "Show network connections to known bad IPs" -k 20
```

#### `dfo report` — Generate NIST Report

Create a structured report covering all four NIST SP 800-86 phases:

```bash
dfo report -c IR-2026-0042 --format markdown --output report.md
dfo report -c IR-2026-0042 --format markdown    # prints to terminal
```

#### `dfo status` — Case Dashboard

View a quick overview of a case:

```bash
dfo status -c IR-2026-0042
```

#### `dfo interactive` — Interactive Session

Launch a REPL-style forensic analysis session:

```bash
dfo interactive --case IR-2026-0042 --analyst "J. Smith"
```

Interactive commands: `ingest`, `score`, `ask`, `status`, `report`, `help`, `quit`

---

## 🔧 External Tool Installation

DFO wraps these CLI tools. Install only the ones you need:

### Network — tshark (Wireshark CLI)

```bash
# Debian / Ubuntu
sudo apt install tshark

# macOS
brew install wireshark

# Verify
tshark --version
```

### Memory — Volatility 3

```bash
pip install volatility3

# Verify
vol --help
```

### Binary — Ghidra (Headless)

1. Download from [ghidra-sre.org](https://ghidra-sre.org)
2. Extract and add `support/analyzeHeadless` to your `PATH`
3. Verify: `analyzeHeadless --help`

### Disk — SleuthKit

```bash
# Debian / Ubuntu
sudo apt install sleuthkit

# macOS
brew install sleuthkit

# Verify
mmls --version && fls --version
```

---

## 📜 NIST Compliance

### SP 800-86 — Chain of Custody

DFO maintains a **JSONL append-only log** for every case at `cases/<CASE_ID>/coc_<CASE_ID>.jsonl`. Each entry records:

| Field | Description |
|-------|-------------|
| `timestamp` | UTC ISO-8601 timestamp |
| `action` | REGISTERED, EXAMINED, ANALYZED |
| `actor` | Analyst name or system identifier |
| `artifact_id` | UUID assigned at registration |
| `sha256_hash` | SHA-256 hash computed at intake |
| `description` | Human-readable action description |
| `nist_phase` | Collection, Examination, Analysis, or Reporting |

### SP 800-61 Rev. 2 — Incident Impact Scoring

The `ArtifactScorer` maps findings to NIST impact categories using a weighted algorithm. Weights are configurable via `dfo.json`:

```json
{
    "scorer_weights": {
        "ioc": 0.40,
        "persistence": 0.30,
        "exfiltration": 0.30
    }
}
```

### Generated Reports

Reports follow the four-phase structure defined in NIST SP 800-86:

1. **Collection** — Evidence intake, hashing, chain of custody
2. **Examination** — Engine execution, raw data extraction
3. **Analysis** — Scoring, ranking, IOC correlation
4. **Reporting** — Automated Markdown/HTML report generation

---

## 🔧 Configuration

### IOC Database Format

Create a JSON file with known-bad indicators:

```json
{
    "ip": ["198.51.100.23", "203.0.113.45"],
    "domain": ["evil-c2.example.com", "malware-drop.example.net"],
    "hash": ["e99a18c428cb38d5f260853678922e03"],
    "mutex": ["Global\\MUTEX_MALWARE_XYZ"],
    "useragent": ["Python-urllib/2.7"]
}
```

Use it with: `dfo score -c <CASE> -i path/to/iocs.json`

### DFO Configuration File

Create a `dfo.json` in the project root to customize defaults:

```json
{
    "case_id": "IR-2026-0042",
    "analyst": "J. Smith",
    "log_dir": "./cases",
    "chroma_dir": "./chroma_db",
    "embedding_model": "all-MiniLM-L6-v2",
    "scorer_weights": {
        "ioc": 0.40,
        "persistence": 0.30,
        "exfiltration": 0.30
    }
}
```

---

## 🧩 Extending DFO

### Adding a New Engine

1. Create a new file in `dfo/engines/`:

```python
# dfo/engines/yara_scanner.py
from dfo.engines.base import BaseEngineAdapter
from dfo.models import ForensicFinding, FindingCategory

class YaraAdapter(BaseEngineAdapter):
    def analyze(self, evidence_path, **kwargs):
        self._check_tool("yara")
        # Your implementation here
        return [ForensicFinding(...)]
```

2. Register it in `dfo/orchestrator.py`:

```python
_ENGINE_CLASSES = {
    ...
    "yara": "dfo.engines.yara_scanner.YaraAdapter",
}
```

3. Add it to the CLI choices in `dfo/cli.py`

### Adding IOC Sources

Enrich the IOC database with STIX/TAXII feeds, MISP exports, or any JSON source matching the format above.

---

## 🧪 Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=dfo

# Lint
ruff check dfo/
```

---

## 📋 Requirements Summary

| Package | Purpose | Required |
|---------|---------|----------|
| `rich` | Colorized terminal output | ✅ Core |
| `click` | CLI framework | ✅ Core |
| `pandas` | Data wrangling | ✅ Core |
| `jinja2` | Report templates | ✅ Core |
| `langchain` | RAG orchestration | Optional (NLI) |
| `chromadb` | Vector store | Optional (NLI) |
| `sentence-transformers` | Embeddings | Optional (NLI) |
| `volatility3` | Memory forensics | Optional |
| `yara-python` | YARA signatures | Optional |

---

## ⚠️ Disclaimer

DFO is a **defensive, post-incident analysis tool**. It examines forensic artifacts that have already been collected through proper legal channels. It does not perform active scanning, exploitation, or any offensive operations. Users are responsible for ensuring evidence is collected and analyzed in compliance with applicable laws and organizational policies.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/yara-engine`)
3. Commit your changes (`git commit -m 'feat: add YARA signature scanning engine'`)
4. Push to the branch (`git push origin feature/yara-engine`)
5. Open a Pull Request

Please ensure all tests pass and code follows the existing style.

---

<p align="center">
  <b>Built for defenders, by defenders.</b><br>
  <sub>If DFO helps your incident response work, consider giving it a ⭐</sub>
</p>
