"""Reusable analysis pipeline shared by the CLI and the web GUI."""

from __future__ import annotations

from typing import Callable, Optional

import anthropic

from .aggregator import aggregate_coverage
from .analyzer import DEFAULT_MODEL, Analyzer
from .ingestion import PolicyDocument
from .knowledge_base import KnowledgeBase
from .models import AnalysisResult

ProgressCallback = Callable[[str], None]


def run_analysis(
    docs: list[PolicyDocument],
    kb: Optional[KnowledgeBase] = None,
    model: str = DEFAULT_MODEL,
    api_key: Optional[str] = None,
    skip_contradictions: bool = False,
    progress: Optional[ProgressCallback] = None,
) -> AnalysisResult:
    """Run the full analysis over a set of loaded policy documents.

    `api_key` overrides the ANTHROPIC_API_KEY environment variable when given
    (used by the web GUI, where the key is entered in the form and held in
    memory only). `progress` receives human-readable status messages.
    """
    notify = progress or (lambda msg: None)
    kb = kb or KnowledgeBase.load()

    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    analyzer = Analyzer(kb, model=model, client=client)

    analyses = {}
    for i, doc in enumerate(docs, 1):
        notify(f"Analyzing policy {i} of {len(docs)}: {doc.name}")
        analyses[doc.name] = analyzer.analyze_policy(doc)

    if skip_contradictions or len(docs) < 2:
        contradictions = []
    else:
        notify("Scanning for cross-policy contradictions")
        contradictions = analyzer.find_contradictions(docs).contradictions

    notify("Aggregating coverage")
    coverage = aggregate_coverage(kb, analyses)
    return AnalysisResult(
        policies=analyses,
        coverage=coverage,
        contradictions=contradictions,
        knowledge_base_version=kb.version,
        model=model,
    )
