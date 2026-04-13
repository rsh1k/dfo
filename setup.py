"""
DFO v2.0 — Digital Forensics Orchestrator (Enterprise Edition)
Install with:  pip install -e ".[all]"
"""

from setuptools import setup, find_packages
from pathlib import Path

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="dfo",
    version="2.0.0",
    description=(
        "Enterprise AI-powered NIST-compliant Digital Forensics "
        "Orchestrator with multi-LLM support"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="rsh1k",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(),
    include_package_data=True,

    entry_points={
        "console_scripts": [
            "dfo=dfo.cli:main",
        ],
    },

    # --- Core (always installed) ---
    install_requires=[
        "rich>=13.0",
        "click>=8.0",
        "pandas>=2.0",
        "jinja2>=3.0",
        "requests>=2.28",
    ],

    extras_require={
        # RAG / NLI (modern 2025 imports)
        "nli": [
            "langchain>=0.3",
            "langchain-core>=0.3",
            "langchain-chroma>=0.2",
            "langchain-huggingface>=0.1",
            "chromadb>=0.4",
            "sentence-transformers>=2.2",
        ],
        # LLM Providers
        "openai": ["openai>=1.0"],
        "anthropic": ["anthropic>=0.30"],
        "ollama": ["ollama>=0.3"],
        "huggingface": ["huggingface_hub>=0.20"],
        # Threat Intelligence
        "threat-intel": [
            "yara-python>=4.3",
            "stix2>=3.0",
            "taxii2-client>=2.3",
        ],
        # Memory forensics
        "volatility": ["volatility3>=2.0"],
        # Log parsing
        "logs": [
            "python-evtx>=0.7",
            "lxml>=4.9",
        ],
        # Cloud forensics
        "cloud": [
            "boto3>=1.28",             # AWS CloudTrail
            "azure-identity>=1.14",    # Azure
            "google-cloud-logging>=3", # GCP
        ],
        # Email forensics
        "email": [
            "extract-msg>=0.40",
            "mail-parser>=3.15",
        ],
        # Everything
        "all": [
            # NLI
            "langchain>=0.3",
            "langchain-core>=0.3",
            "langchain-chroma>=0.2",
            "langchain-huggingface>=0.1",
            "chromadb>=0.4",
            "sentence-transformers>=2.2",
            # LLMs
            "openai>=1.0",
            "anthropic>=0.30",
            "ollama>=0.3",
            "huggingface_hub>=0.20",
            # Threat Intel
            "yara-python>=4.3",
            "stix2>=3.0",
            "taxii2-client>=2.3",
            # Forensics
            "volatility3>=2.0",
            "python-evtx>=0.7",
            "lxml>=4.9",
        ],
        # Dev
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
            "ruff",
            "mypy",
        ],
    },
)
