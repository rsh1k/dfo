"""
dfo/ai_engine.py
================
Multi-LLM AI Engine for automated forensic analysis.

Supports: OpenAI, Anthropic, Ollama (local), HuggingFace Inference API.
Provides: automated finding analysis, IOC enrichment, MITRE mapping suggestions,
          natural language case summarization, and threat assessment.

Install providers as needed:
    pip install openai          # for OpenAI
    pip install anthropic       # for Anthropic
    pip install ollama          # for Ollama (local)
    pip install huggingface_hub # for HuggingFace
"""

from __future__ import annotations

import json
import os
import logging
from typing import Optional

from dfo.models import (
    ForensicFinding, LLMConfig, LLMProvider, MITREMapping
)
from dfo.terminal import print_info, print_warning, print_error

logger = logging.getLogger("DFO.AI")


class AIEngine:
    """
    Unified LLM interface for forensic AI analysis.
    Automatically dispatches to the configured provider.
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None
        self._initialized = False

        if config.provider == LLMProvider.NONE:
            print_warning("AI Engine disabled — no LLM provider configured")
            return

        self._init_client()

    def _init_client(self):
        """Lazy-initialize the LLM client."""
        cfg = self.config

        try:
            if cfg.provider == LLMProvider.OPENAI:
                import openai
                api_key = os.environ.get(cfg.api_key, cfg.api_key)
                self._client = openai.OpenAI(api_key=api_key)
                self._initialized = True

            elif cfg.provider == LLMProvider.ANTHROPIC:
                import anthropic
                api_key = os.environ.get(cfg.api_key, cfg.api_key)
                self._client = anthropic.Anthropic(api_key=api_key)
                self._initialized = True

            elif cfg.provider == LLMProvider.OLLAMA:
                import ollama
                self._client = ollama.Client(host=cfg.api_base)
                self._initialized = True

            elif cfg.provider == LLMProvider.HUGGINGFACE:
                from huggingface_hub import InferenceClient
                api_key = os.environ.get(cfg.api_key, cfg.api_key)
                self._client = InferenceClient(
                    model=cfg.model, token=api_key
                )
                self._initialized = True

            if self._initialized:
                print_info(
                    f"AI Engine initialized: "
                    f"[bold]{cfg.provider.value}[/bold] / "
                    f"[bold]{cfg.model}[/bold]"
                )

        except ImportError as e:
            print_error(
                f"Missing dependency for {cfg.provider.value}: {e}. "
                f"Install it with pip."
            )
        except Exception as e:
            print_error(f"Failed to initialize AI engine: {e}")

    @property
    def available(self) -> bool:
        return self._initialized and self._client is not None

    # ---------------------------------------------------------------
    # Core completion method — dispatches to provider
    # ---------------------------------------------------------------

    def _complete(self, system_prompt: str, user_prompt: str,
                  temperature: Optional[float] = None,
                  max_tokens: Optional[int] = None) -> str:
        """Send a prompt to the configured LLM and return the response."""
        if not self.available:
            return ""

        temp = temperature or self.config.temperature
        tokens = max_tokens or self.config.max_tokens

        try:
            if self.config.provider == LLMProvider.OPENAI:
                resp = self._client.chat.completions.create(
                    model=self.config.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temp,
                    max_tokens=tokens,
                )
                return resp.choices[0].message.content or ""

            elif self.config.provider == LLMProvider.ANTHROPIC:
                resp = self._client.messages.create(
                    model=self.config.model,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temp,
                    max_tokens=tokens,
                )
                return resp.content[0].text or ""

            elif self.config.provider == LLMProvider.OLLAMA:
                resp = self._client.chat(
                    model=self.config.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    options={"temperature": temp, "num_predict": tokens},
                )
                return resp["message"]["content"] or ""

            elif self.config.provider == LLMProvider.HUGGINGFACE:
                resp = self._client.text_generation(
                    prompt=f"{system_prompt}\n\n{user_prompt}",
                    max_new_tokens=tokens,
                    temperature=temp,
                )
                return resp or ""

        except Exception as e:
            logger.error("LLM completion failed: %s", e)
            return f"[AI Error: {e}]"

        return ""

    # ---------------------------------------------------------------
    # Forensic analysis methods
    # ---------------------------------------------------------------

    FORENSIC_SYSTEM_PROMPT = """You are an expert DFIR (Digital Forensics and Incident Response) analyst.
You analyze forensic findings and provide actionable intelligence.
Always respond in structured JSON when asked for structured output.
Be precise, technical, and reference MITRE ATT&CK techniques where applicable.
Focus on: what happened, severity, impact, and recommended response actions."""

    def analyze_finding(self, finding: ForensicFinding) -> dict:
        """
        AI-powered analysis of a single forensic finding.
        Returns summary, risk assessment, MITRE mapping suggestions,
        and recommended response actions.
        """
        prompt = f"""Analyze this forensic finding and respond with JSON:

Category: {finding.category.value}
Engine: {finding.engine}
Title: {finding.title}
Description: {finding.description}
Raw Data: {json.dumps(finding.raw_data, default=str)[:2000]}
IOC Matches: {finding.ioc_matches}
Persistence Indicators: {finding.persistence_indicators}
Exfiltration Indicators: {finding.exfil_indicators}
Current Score: {finding.severity_score}

Respond ONLY with this JSON structure:
{{
    "summary": "1-2 sentence analysis",
    "risk_level": "critical|high|medium|low|info",
    "risk_score_adjustment": 0.0,
    "mitre_techniques": [
        {{"technique_id": "T1xxx", "technique_name": "...", "tactic": "...", "confidence": 0.0-1.0}}
    ],
    "iocs_extracted": ["ip/domain/hash found"],
    "recommended_actions": ["action 1", "action 2"],
    "is_malicious": true/false,
    "confidence": 0.0-1.0
}}"""

        raw = self._complete(self.FORENSIC_SYSTEM_PROMPT, prompt)
        try:
            # Strip markdown code fences if present
            clean = raw.strip()
            if clean.startswith("```"):
                clean = clean.split("\n", 1)[1]
            if clean.endswith("```"):
                clean = clean.rsplit("```", 1)[0]
            return json.loads(clean)
        except (json.JSONDecodeError, IndexError):
            return {"summary": raw[:500], "error": "Failed to parse JSON"}

    def analyze_findings_batch(self,
                                findings: list[ForensicFinding]) -> str:
        """Analyze a batch of findings and produce a case narrative."""
        summaries = []
        for f in findings[:50]:  # Limit to avoid token overflow
            summaries.append(
                f"- [{f.severity.value}] {f.category.value}/{f.engine}: "
                f"{f.description[:150]}"
            )

        prompt = f"""You are reviewing {len(findings)} forensic findings from a DFIR case.
Here are the top findings:

{chr(10).join(summaries)}

Provide a narrative incident summary covering:
1. What likely happened (attack timeline)
2. Key indicators of compromise found
3. MITRE ATT&CK techniques observed
4. Immediate containment recommendations
5. Long-term remediation steps

Write in professional DFIR report style."""

        return self._complete(self.FORENSIC_SYSTEM_PROMPT, prompt)

    def suggest_mitre_mappings(self,
                                finding: ForensicFinding) -> list[MITREMapping]:
        """Use AI to suggest MITRE ATT&CK technique mappings."""
        prompt = f"""Given this forensic finding, suggest relevant MITRE ATT&CK techniques.

Finding: {finding.title} — {finding.description[:300]}
Category: {finding.category.value}

Respond ONLY with a JSON array:
[{{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "confidence": 0.8}}]

Return empty array [] if no techniques apply."""

        raw = self._complete(self.FORENSIC_SYSTEM_PROMPT, prompt,
                             max_tokens=1024)
        try:
            clean = raw.strip()
            if clean.startswith("```"):
                clean = clean.split("\n", 1)[1]
            if clean.endswith("```"):
                clean = clean.rsplit("```", 1)[0]
            data = json.loads(clean)
            return [
                MITREMapping(
                    technique_id=d.get("technique_id", ""),
                    technique_name=d.get("technique_name", ""),
                    tactic=d.get("tactic", ""),
                    confidence=float(d.get("confidence", 0.5)),
                )
                for d in data
            ]
        except (json.JSONDecodeError, TypeError):
            return []

    def natural_language_query(self, question: str,
                                context: str) -> str:
        """Answer a natural language question about forensic data."""
        prompt = f"""A forensic analyst asks: "{question}"

Here is the relevant forensic context:
{context[:6000]}

Answer the question based ONLY on the provided context.
If the answer isn't in the context, say so.
Be specific — reference IPs, timestamps, processes, and file names."""

        return self._complete(self.FORENSIC_SYSTEM_PROMPT, prompt)

    def generate_ioc_report(self, iocs: list[str]) -> str:
        """Generate an IOC report with context and recommendations."""
        prompt = f"""Generate a threat intelligence report for these IOCs:

{chr(10).join(f'- {ioc}' for ioc in iocs[:100])}

Include: classification, known associations, risk level, and blocking recommendations."""

        return self._complete(self.FORENSIC_SYSTEM_PROMPT, prompt)
