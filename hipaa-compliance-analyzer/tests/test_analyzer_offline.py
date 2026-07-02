"""Offline tests: everything except the actual API calls.

Run with: python -m pytest tests/ (or python -m unittest discover tests)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hipaa_analyzer.aggregator import aggregate_coverage, coverage_stats
from hipaa_analyzer.ingestion import IngestionError, load_directory
from hipaa_analyzer.knowledge_base import KnowledgeBase
from hipaa_analyzer.models import (
    AnalysisResult,
    CitationMapping,
    Contradiction,
    PolicyAnalysis,
)
from hipaa_analyzer.report import render_markdown

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "sample_policies"


def make_analysis(*mappings: tuple[str, str]) -> PolicyAnalysis:
    return PolicyAnalysis(
        policy_summary="Test policy.",
        topics=["testing"],
        citations_addressed=[
            CitationMapping(citation=c, coverage=cov, evidence="quoted text", notes="note")
            for c, cov in mappings
        ],
        internal_issues=[],
    )


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.kb = KnowledgeBase.load()

    def test_loads_all_three_rules(self):
        rules = {r.rule for r in self.kb.requirements}
        self.assertEqual(rules, {"privacy", "security", "breach"})

    def test_core_citations_present(self):
        for citation in [
            "164.308(a)(1)(ii)(A)",  # risk analysis
            "164.312(a)(2)(i)",      # unique user ID
            "164.524",               # right of access
            "164.404",               # breach notice to individuals
            "164.530(b)",            # privacy training
        ]:
            self.assertIsNotNone(self.kb.get(citation), citation)

    def test_get_tolerates_prefixes(self):
        self.assertIsNotNone(self.kb.get("45 CFR §164.524"))
        self.assertIsNotNone(self.kb.get("§164.524"))

    def test_reference_text_contains_every_citation(self):
        text = self.kb.to_reference_text()
        for r in self.kb.requirements:
            self.assertIn(r.citation, text)


class IngestionTests(unittest.TestCase):
    def test_loads_sample_policies(self):
        docs = load_directory(EXAMPLES)
        names = {d.name for d in docs}
        self.assertIn("information_security_policy.md", names)
        self.assertEqual(len(docs), 3)
        for d in docs:
            self.assertGreater(len(d.text), 100)

    def test_empty_directory_raises(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(IngestionError):
                load_directory(tmp)


class AggregatorTests(unittest.TestCase):
    def setUp(self):
        self.kb = KnowledgeBase.load()

    def test_full_coverage_from_one_policy(self):
        analyses = {"a.md": make_analysis(("164.524", "full"))}
        cov = {c.citation: c for c in aggregate_coverage(self.kb, analyses)}
        self.assertEqual(cov["164.524"].status, "covered")

    def test_single_partial_is_partial(self):
        analyses = {"a.md": make_analysis(("164.524", "partial"))}
        cov = {c.citation: c for c in aggregate_coverage(self.kb, analyses)}
        self.assertEqual(cov["164.524"].status, "partial")

    def test_two_partials_across_policies_combine_to_covered(self):
        analyses = {
            "a.md": make_analysis(("164.524", "partial")),
            "b.md": make_analysis(("164.524", "partial")),
        }
        cov = {c.citation: c for c in aggregate_coverage(self.kb, analyses)}
        self.assertEqual(cov["164.524"].status, "covered")
        self.assertEqual(len(cov["164.524"].contributions), 2)

    def test_unaddressed_requirement_is_missing(self):
        analyses = {"a.md": make_analysis(("164.524", "full"))}
        cov = {c.citation: c for c in aggregate_coverage(self.kb, analyses)}
        self.assertEqual(cov["164.404"].status, "missing")

    def test_stats_add_up(self):
        analyses = {"a.md": make_analysis(("164.524", "full"), ("164.526", "partial"))}
        stats = coverage_stats(aggregate_coverage(self.kb, analyses))
        self.assertEqual(
            stats["covered"] + stats["partial"] + stats["missing"], stats["total"]
        )
        self.assertEqual(stats["total"], len(self.kb.requirements))


class ReportTests(unittest.TestCase):
    def test_report_renders_all_sections(self):
        kb = KnowledgeBase.load()
        analyses = {
            "a.md": make_analysis(("164.524", "full")),
            "b.md": make_analysis(("164.526", "partial")),
        }
        result = AnalysisResult(
            policies=analyses,
            coverage=aggregate_coverage(kb, analyses),
            contradictions=[
                Contradiction(
                    policy_a="a.md",
                    policy_b="b.md",
                    topic="Session timeout",
                    description="Different timeout values.",
                    excerpt_a="15 minutes",
                    excerpt_b="5 minutes",
                    severity="medium",
                    recommendation="Pick one value.",
                )
            ],
            knowledge_base_version=kb.version,
            model="claude-opus-4-8",
        )
        md = render_markdown(result, org_name="Test Clinic")
        for expected in [
            "# HIPAA Policy Compliance Gap Analysis — Test Clinic",
            "## Executive Summary",
            "## Gaps: Requirements Not Addressed by Any Policy",
            "## Partially Addressed Requirements",
            "## Contradictions Between Policies",
            "MEDIUM: Session timeout",
            "## Full Coverage Matrix",
            "## Per-Policy Detail",
            "§164.524",
        ]:
            self.assertIn(expected, md)


if __name__ == "__main__":
    unittest.main()
