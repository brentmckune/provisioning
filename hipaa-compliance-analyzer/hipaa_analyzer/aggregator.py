"""Deterministic aggregation of per-policy analyses into requirement coverage.

A requirement may be satisfied across several policies (one covers the
"what", another the "who", a third the procedure). Aggregation keeps every
contribution so the report can show exactly which policies combine to cover
each requirement — and applies an honest rule for overall status:

- covered  — at least one policy fully satisfies the requirement, OR two or
             more policies each partially address it (flagged in the report
             as "combined coverage — verify the pieces together are complete").
- partial  — exactly one policy addresses it, and only partially.
- missing  — no policy addresses it at all.
"""

from __future__ import annotations

from .knowledge_base import KnowledgeBase
from .models import (
    PolicyAnalysis,
    PolicyContribution,
    RequirementCoverage,
)


def aggregate_coverage(
    kb: KnowledgeBase, analyses: dict[str, PolicyAnalysis]
) -> list[RequirementCoverage]:
    contributions: dict[str, list[PolicyContribution]] = {}
    for policy_name, analysis in analyses.items():
        for m in analysis.citations_addressed:
            contributions.setdefault(m.citation, []).append(
                PolicyContribution(
                    policy=policy_name,
                    coverage=m.coverage,
                    evidence=m.evidence,
                    notes=m.notes,
                )
            )

    results: list[RequirementCoverage] = []
    for req in kb.requirements:
        contribs = contributions.get(req.citation, [])
        if any(c.coverage == "full" for c in contribs):
            status = "covered"
        elif len(contribs) >= 2:
            # Multiple partial contributions: treated as combined coverage,
            # surfaced with a verification note in the report.
            status = "covered"
        elif len(contribs) == 1:
            status = "partial"
        else:
            status = "missing"
        results.append(
            RequirementCoverage(
                citation=req.citation,
                title=req.title,
                rule=req.rule,
                category=req.category,
                type=req.type,
                status=status,
                contributions=contribs,
            )
        )
    return results


def coverage_stats(coverage: list[RequirementCoverage]) -> dict[str, int]:
    stats = {"covered": 0, "partial": 0, "missing": 0, "total": len(coverage)}
    for c in coverage:
        stats[c.status] += 1
    return stats
