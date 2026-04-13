"""
DFO - Digital Forensics Orchestrator
Install with:  pip install -e ".[all]"
"""

from setuptools import setup, find_packages
from pathlib import Path

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="dfo",
    version="1.0.0",
    description="NIST-compliant Digital Forensics Orchestrator with NL querying",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Security Team",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "dfo=dfo.cli:main",
        ],
    },
    install_requires=[
        "rich>=13.0",
        "click>=8.0",
        "pandas>=2.0",
        "jinja2>=3.0",
    ],
    extras_require={
        "nli": [
            "langchain>=0.2",
            "langchain-community>=0.2",
            "chromadb>=0.4",
            "sentence-transformers>=2.2",
        ],
        "volatility": [
            "volatility3>=2.0",
        ],
        "yara": [
            "yara-python>=4.3",
        ],
        "all": [
            "langchain>=0.2",
            "langchain-community>=0.2",
            "chromadb>=0.4",
            "sentence-transformers>=2.2",
            "volatility3>=2.0",
            "yara-python>=4.3",
        ],
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
            "ruff",
        ],
    },
)
