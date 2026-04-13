"""
dfo/nli.py
==========
Natural Language Interface — RAG layer using LangChain + ChromaDB.
Indexes ForensicFindings and answers English queries via semantic search.
"""

from __future__ import annotations

from dfo.models import ForensicFinding
from dfo.terminal import console, print_info


class NaturalLanguageInterface:
    """
    RAG layer using LangChain + ChromaDB for semantic search
    over forensic findings.

    Usage:
        nli = NaturalLanguageInterface()
        nli.index_findings(scored_findings)
        answer = nli.query("Show suspicious outbound connections")
    """

    def __init__(self, collection_name: str = "dfir_findings",
                 persist_dir: str = "./chroma_db",
                 embedding_model: str = "all-MiniLM-L6-v2"):
        from langchain_community.vectorstores import Chroma
        from langchain_community.embeddings import HuggingFaceEmbeddings
        from langchain.schema import Document

        self._Document = Document
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.vectorstore = Chroma(
            collection_name=collection_name,
            embedding_function=self.embeddings,
            persist_directory=persist_dir,
        )
        print_info("Vector store initialized")

    def index_findings(self, findings: list[ForensicFinding]):
        """Convert findings into LangChain Documents and add to vector store."""
        docs = []
        for f in findings:
            text = (
                f"[{f.category.value}] ({f.engine}) {f.title}\n"
                f"Severity: {f.severity_score:.3f} ({f.severity.value})\n"
                f"Description: {f.description}\n"
                f"IOCs: {', '.join(f.ioc_matches) or 'none'}\n"
                f"Persistence: {', '.join(f.persistence_indicators) or 'none'}\n"
                f"Exfiltration: {', '.join(f.exfil_indicators) or 'none'}"
            )
            docs.append(self._Document(
                page_content=text,
                metadata={
                    "finding_id": f.id,
                    "category": f.category.value,
                    "engine": f.engine,
                    "severity": f.severity_score,
                },
            ))
        self.vectorstore.add_documents(docs)
        print_info(f"Indexed [bold]{len(docs)}[/bold] findings into vector store")

    def query(self, question: str, top_k: int = 10) -> dict:
        """
        Retrieve relevant findings via semantic search.
        Returns the retrieved context and a formatted answer.
        """
        results = self.vectorstore.similarity_search_with_score(question, k=top_k)
        context_blocks = []
        for doc, score in results:
            context_blocks.append({
                "text": doc.page_content,
                "metadata": doc.metadata,
                "relevance": round(1 - score, 4),
            })
        return {
            "query": question,
            "retrieved_count": len(context_blocks),
            "findings": context_blocks,
        }
