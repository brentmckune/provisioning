"""Pydantic models for structured analysis results."""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class CitationMapping(BaseModel):
    """One HIPAA requirement addressed (fully or partially) by a policy."""

    citation: str = Field(
        description="The CFR citation exactly as it appears in the reference list, e.g. '164.308(a)(1)(ii)(A)'."
    )
    coverage: Literal["full", "partial"] = Field(
        description="'full' if the policy substantively satisfies the requirement on its own; "
        "'partial' if it addresses only part of the requirement or addresses it superficially."
    )
    evidence: str = Field(
        description="A short verbatim quote from the policy showing where the requirement is addressed."
    )
    notes: str = Field(
        description="For partial coverage: what part of the requirement is addressed and what is missing. "
        "For full coverage: a one-line justification."
    )


class PolicyAnalysis(BaseModel):
    """Structured analysis of a single policy document."""

    policy_summary: str = Field(
        description="Two to three sentences summarizing what this policy covers."
    )
    topics: List[str] = Field(
        description="Short topic tags for the subject areas the policy covers, e.g. 'access control', 'breach notification'."
    )
    citations_addressed: List[CitationMapping] = Field(
        description="Every requirement from the reference list that this policy addresses fully or partially. "
        "Only include citations from the reference list."
    )
    internal_issues: List[str] = Field(
        description="Statements inside this policy that are internally inconsistent, ambiguous, or that appear "
        "to conflict with HIPAA itself (e.g. a retention period shorter than 6 years). Empty list if none."
    )


class Contradiction(BaseModel):
    """A conflict between statements in two different policies."""

    policy_a: str = Field(description="Filename of the first policy, exactly as given.")
    policy_b: str = Field(description="Filename of the second policy, exactly as given.")
    topic: str = Field(description="The subject the two policies disagree about.")
    description: str = Field(
        description="Plain-language explanation of how the two policies contradict each other."
    )
    excerpt_a: str = Field(description="Verbatim quote from policy_a showing its position.")
    excerpt_b: str = Field(description="Verbatim quote from policy_b showing its conflicting position.")
    severity: Literal["high", "medium", "low"] = Field(
        description="'high' if the conflict could cause a HIPAA violation or leave staff unable to know which "
        "rule to follow on a compliance-critical matter; 'medium' if it creates meaningful operational "
        "ambiguity; 'low' for minor inconsistencies."
    )
    recommendation: str = Field(description="How to reconcile the two policies.")


class ContradictionReport(BaseModel):
    contradictions: List[Contradiction] = Field(
        description="All genuine contradictions found between the policies. Empty list if none. "
        "Do not report mere differences in scope or level of detail as contradictions."
    )


# ---------------------------------------------------------------------------
# Aggregated results (computed in code, not by the model)
# ---------------------------------------------------------------------------


class PolicyContribution(BaseModel):
    """How one policy contributes to coverage of one requirement."""

    policy: str
    coverage: Literal["full", "partial"]
    evidence: str
    notes: str


class RequirementCoverage(BaseModel):
    """Aggregated coverage status of one HIPAA requirement across all policies."""

    citation: str
    title: str
    rule: str
    category: str
    type: str
    status: Literal["covered", "partial", "missing"]
    contributions: List[PolicyContribution] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Full result of an analysis run."""

    policies: dict[str, PolicyAnalysis]
    coverage: List[RequirementCoverage]
    contradictions: List[Contradiction]
    knowledge_base_version: str
    model: Optional[str] = None
