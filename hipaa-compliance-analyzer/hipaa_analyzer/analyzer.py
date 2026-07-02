"""LLM-powered analysis: maps policies to HIPAA requirements and finds contradictions.

Design notes:
- The regulation knowledge base is placed in the system prompt with a
  cache_control breakpoint, so analyzing N policies pays for the reference
  text once and reads it from cache for the remaining N-1 calls.
- Structured outputs (client.messages.parse with Pydantic models) guarantee
  parseable results for both the per-policy mapping and the contradiction scan.
- Coverage aggregation across policies is deterministic Python (see
  aggregator.py), not model output — a requirement counts as covered even when
  its pieces live in different policies, and the report shows exactly which
  policy contributed which piece.
"""

from __future__ import annotations

import anthropic

from .ingestion import PolicyDocument
from .knowledge_base import KnowledgeBase
from .models import ContradictionReport, PolicyAnalysis

DEFAULT_MODEL = "claude-opus-4-8"

_SYSTEM_ROLE = """You are a HIPAA compliance analyst reviewing a healthcare organization's \
policies and procedures. You cross-reference policy text against the HIPAA Privacy Rule, \
Security Rule, and Breach Notification Rule requirements listed below.

Rules for your analysis:
- Only cite requirements from the reference list, using the citation string exactly as written there.
- A requirement is 'full' coverage only when the policy substantively satisfies it: it states \
what must be done, by whom, and with enough specificity that a workforce member could follow it. \
Mere mentions, vague commitments ("we protect patient data"), or coverage of only one prong of a \
multi-part requirement are 'partial'.
- A single policy often addresses only part of a requirement; another policy may address the rest. \
Record exactly what THIS document covers — the parts are combined across policies later, so be \
precise in the notes about which part is present and which is absent.
- Quote evidence verbatim and keep quotes under 40 words.
- Do not invent coverage. If a requirement is not addressed in the document, do not list it."""

_REFERENCE_HEADER = "HIPAA REQUIREMENTS REFERENCE LIST:\n"

_CONTRADICTION_SYSTEM = """You are a HIPAA compliance analyst reviewing a healthcare organization's \
complete set of policies and procedures for internal contradictions.

A contradiction is when two policies give conflicting directions on the same subject — different \
retention periods for the same records, different deadlines for the same notification, one policy \
permitting what another prohibits, conflicting responsible parties for the same duty, incompatible \
technical requirements (e.g. different session-timeout values for the same systems), or conflicting \
procedures a workforce member could not follow simultaneously.

NOT contradictions: one policy being more detailed than another on the same subject, two policies \
covering different scopes (e.g. paper records vs electronic records), or a policy simply not \
mentioning a topic another covers. Only report genuine conflicts, with verbatim excerpts."""


class Analyzer:
    def __init__(
        self,
        kb: KnowledgeBase,
        model: str = DEFAULT_MODEL,
        client: anthropic.Anthropic | None = None,
    ):
        self.kb = kb
        self.model = model
        self.client = client or anthropic.Anthropic()
        # Stable system block with a cache breakpoint: identical across all
        # per-policy calls in a run, so calls 2..N read it from cache.
        self._policy_system = [
            {
                "type": "text",
                "text": _SYSTEM_ROLE + "\n\n" + _REFERENCE_HEADER + kb.to_reference_text(),
                "cache_control": {"type": "ephemeral"},
            }
        ]

    def analyze_policy(self, doc: PolicyDocument) -> PolicyAnalysis:
        """Map one policy document to the HIPAA requirements it addresses."""
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=self._policy_system,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Analyze the following policy document.\n\n"
                        f"FILENAME: {doc.name}\n\n"
                        f"<policy_document>\n{doc.text}\n</policy_document>"
                    ),
                }
            ],
            output_format=PolicyAnalysis,
        )
        analysis = response.parsed_output
        if analysis is None:
            raise RuntimeError(f"Model returned unparseable analysis for {doc.name}")
        return self._validate_citations(doc.name, analysis)

    def _validate_citations(self, name: str, analysis: PolicyAnalysis) -> PolicyAnalysis:
        """Drop any citation the model produced that isn't in the knowledge base."""
        valid, dropped = [], []
        for m in analysis.citations_addressed:
            req = self.kb.get(m.citation)
            if req is None:
                dropped.append(m.citation)
            else:
                m.citation = req.citation  # normalize formatting
                valid.append(m)
        if dropped:
            print(f"warning: {name}: dropped unrecognized citations: {', '.join(dropped)}")
        analysis.citations_addressed = valid
        return analysis

    def find_contradictions(self, docs: list[PolicyDocument]) -> ContradictionReport:
        """Scan the whole policy set for cross-policy contradictions in one call.

        All documents are sent together (the 1M-token context window covers a
        typical policy manual) so the model can compare every pair directly.
        """
        if len(docs) < 2:
            return ContradictionReport(contradictions=[])

        corpus = "\n\n".join(
            f"<policy filename=\"{d.name}\">\n{d.text}\n</policy>" for d in docs
        )
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=_CONTRADICTION_SYSTEM,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Review this complete set of policies for contradictions "
                        "between documents.\n\n" + corpus
                    ),
                }
            ],
            output_format=ContradictionReport,
        )
        report = response.parsed_output
        if report is None:
            raise RuntimeError("Model returned an unparseable contradiction report")
        known = {d.name for d in docs}
        report.contradictions = [
            c for c in report.contradictions if c.policy_a in known and c.policy_b in known
        ]
        return report
