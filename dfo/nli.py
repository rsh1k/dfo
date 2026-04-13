"""
dfo/nli.py
==========
Natural Language Interface — RAG layer with AI-enhanced responses.
Uses modern 2025 LangChain imports.
"""

from __future__ import annotations

import json
from typing import Optional

from dfo.models import ForensicFinding, LLMConfig, LLMProvider
from dfo.terminal import console, print_info


class NaturalLanguageInterface:
    """RAG layer: semantic search + optional LLM synthesis."""

    def __init__(self, collection_name: str = "dfir_findings",
                 persist_dir: str = "./chroma_db",
                 embedding_model: str = "all-MiniLM-L6-v2",
                 llm_config: Optional[LLMConfig] = None):
        from langchain_chroma import Chroma
        from langchain_huggingface import HuggingFaceEmbeddings

        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.vectorstore = Chroma(
            collection_name=collection_name,
            embedding_function=self.embeddings,
            persist_directory=persist_dir,
        )
        self.llm_config = llm_config
        self._ai_engine = None

        if llm_config and llm_config.provider != LLMProvider.NONE:
            try:
                from dfo.ai_engine import AIEngine
                self._ai_engine = AIEngine(llm_config)
            except Exception:
                pass

        print_info("Vector store initialized")

    def index_findings(self, findings: list[ForensicFinding]):
        """Index findings into the vector store."""
        from langchain_core.documents import Document

        docs = []
        for f in findings:
            raw_summary = self._summarize_raw_data(f.raw_data)

            text = (
                f"Category: {f.category.value}\n"
                f"Engine: {f.engine}\n"
                f"Title: {f.title}\n"
                f"Severity: {f.severity_score:.3f} ({f.severity.value})\n"
                f"Description: {f.description}\n"
                f"Data: {raw_summary}\n"
                f"IOCs: {', '.join(f.ioc_matches) or 'none'}\n"
                f"Persistence: {', '.join(f.persistence_indicators) or 'none'}\n"
                f"Exfiltration: {', '.join(f.exfil_indicators) or 'none'}"
            )

            docs.append(Document(
                page_content=text,
                metadata={
                    "finding_id": f.id,
                    "category": f.category.value,
                    "engine": f.engine,
                    "severity": f.severity_score,
                    "title": f.title or "Untitled",
                    "description": f.description or "No description",
                },
            ))

        self.vectorstore.add_documents(docs)
        print_info(f"Indexed [bold]{len(docs)}[/bold] findings into vector store")

    def query(self, question: str, top_k: int = 10) -> dict:
        """Semantic search with optional AI synthesis."""
        results = self.vectorstore.similarity_search_with_score(
            question, k=top_k
        )

        context_blocks = []
        for doc, distance in results:
            relevance = round(1.0 / (1.0 + distance), 4)
            context_blocks.append({
                "text": doc.page_content,
                "metadata": doc.metadata,
                "relevance": relevance,
            })

        context_blocks.sort(key=lambda x: x["relevance"], reverse=True)

        ai_answer = ""
        if self._ai_engine and self._ai_engine.available:
            combined = "\n\n---\n\n".join(
                b["text"] for b in context_blocks[:5]
            )
            ai_answer = self._ai_engine.natural_language_query(
                question, combined
            )

        return {
            "query": question,
            "retrieved_count": len(context_blocks),
            "findings": context_blocks,
            "ai_answer": ai_answer,
        }

    @staticmethod
    def _summarize_raw_data(raw_data: dict) -> str:
        """Extract key forensic fields into searchable text."""
        parts = []
        key_fields = [
            "src_ip", "dst_ip", "ip", "ip_src", "ip_dst",
            "query_name", "resolved_a", "resolved_aaaa",
            "host", "uri", "method", "user_agent", "sni",
            "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport",
            "protocols", "protocol", "info",
            "frames", "bytes", "packets",
            "plugin", "api", "entry",
        ]
        for key in key_fields:
            val = raw_data.get(key)
            if val and str(val).strip():
                parts.append(f"{key}={val}")
        for fallback in ["line", "record"]:
            val = raw_data.get(fallback)
            if val:
                parts.append(str(val)[:200])
        return " | ".join(parts) if parts else "no additional data"
