"""Markdown report generation."""

from __future__ import annotations

from datetime import date

from .aggregator import coverage_stats
from .models import AnalysisResult, RequirementCoverage

_RULE_NAMES = {
    "privacy": "Privacy Rule (45 CFR Part 164, Subpart E)",
    "security": "Security Rule (45 CFR Part 164, Subpart C)",
    "breach": "Breach Notification Rule (45 CFR Part 164, Subpart D)",
}

_STATUS_ICONS = {"covered": "✅", "partial": "🟡", "missing": "❌"}


def _pct(n: int, total: int) -> str:
    return f"{100 * n / total:.0f}%" if total else "n/a"


def _combined_note(cov: RequirementCoverage) -> str:
    if cov.status == "covered" and not any(c.coverage == "full" for c in cov.contributions):
        return " *(combined coverage from multiple policies — verify the pieces together are complete)*"
    return ""


def render_markdown(result: AnalysisResult, org_name: str | None = None) -> str:
    lines: list[str] = []
    stats = coverage_stats(result.coverage)

    title = "HIPAA Policy Compliance Gap Analysis"
    if org_name:
        title += f" — {org_name}"
    lines += [f"# {title}", ""]
    lines += [
        f"*Generated {date.today().isoformat()} · "
        f"{len(result.policies)} policies analyzed · "
        f"knowledge base v{result.knowledge_base_version}"
        + (f" · model {result.model}*" if result.model else "*"),
        "",
    ]

    # ------------------------------------------------------------- summary
    lines += ["## Executive Summary", ""]
    lines += [
        f"Of **{stats['total']}** HIPAA requirements checked:",
        "",
        f"- ✅ **{stats['covered']} covered** ({_pct(stats['covered'], stats['total'])})",
        f"- 🟡 **{stats['partial']} partially covered** ({_pct(stats['partial'], stats['total'])})",
        f"- ❌ **{stats['missing']} missing** ({_pct(stats['missing'], stats['total'])})",
        "",
    ]
    high_contradictions = [c for c in result.contradictions if c.severity == "high"]
    if result.contradictions:
        lines += [
            f"**{len(result.contradictions)} contradiction(s)** were found between policies"
            + (f", including **{len(high_contradictions)} high-severity**." if high_contradictions else "."),
            "",
        ]
    else:
        lines += ["No contradictions were detected between policies.", ""]

    # ------------------------------------------------------ missing first
    missing = [c for c in result.coverage if c.status == "missing"]
    partial = [c for c in result.coverage if c.status == "partial"]

    lines += ["## Gaps: Requirements Not Addressed by Any Policy", ""]
    if not missing:
        lines += ["None — every requirement in the knowledge base is addressed by at least one policy.", ""]
    else:
        for rule_key, rule_name in _RULE_NAMES.items():
            rule_missing = [c for c in missing if c.rule == rule_key]
            if not rule_missing:
                continue
            lines += [f"### {rule_name}", ""]
            for cov in rule_missing:
                lines += [
                    f"- ❌ **§{cov.citation} — {cov.title}** ({cov.type}, {cov.category})",
                ]
            lines += [""]

    lines += ["## Partially Addressed Requirements", ""]
    if not partial:
        lines += ["None.", ""]
    else:
        for cov in partial:
            c = cov.contributions[0]
            lines += [
                f"### 🟡 §{cov.citation} — {cov.title}",
                "",
                f"*{cov.type}, {cov.category}*",
                "",
                f"- Addressed only in **{c.policy}**: {c.notes}",
                f"  - Evidence: “{c.evidence}”",
                "",
            ]

    # ------------------------------------------------------ contradictions
    lines += ["## Contradictions Between Policies", ""]
    if not result.contradictions:
        lines += ["None detected.", ""]
    else:
        order = {"high": 0, "medium": 1, "low": 2}
        for c in sorted(result.contradictions, key=lambda x: order[x.severity]):
            lines += [
                f"### {c.severity.upper()}: {c.topic}",
                "",
                f"**{c.policy_a}** vs **{c.policy_b}**",
                "",
                c.description,
                "",
                f"- *{c.policy_a}*: “{c.excerpt_a}”",
                f"- *{c.policy_b}*: “{c.excerpt_b}”",
                "",
                f"**Recommendation:** {c.recommendation}",
                "",
            ]

    # -------------------------------------------------- full coverage matrix
    lines += ["## Full Coverage Matrix", ""]
    for rule_key, rule_name in _RULE_NAMES.items():
        rule_cov = [c for c in result.coverage if c.rule == rule_key]
        if not rule_cov:
            continue
        lines += [f"### {rule_name}", ""]
        lines += ["| Status | Citation | Requirement | Type | Addressed in |", "|---|---|---|---|---|"]
        for cov in rule_cov:
            where = (
                "; ".join(f"{c.policy} ({c.coverage})" for c in cov.contributions)
                if cov.contributions
                else "—"
            )
            note = " ⚠" if _combined_note(cov) else ""
            lines.append(
                f"| {_STATUS_ICONS[cov.status]}{note} | §{cov.citation} | {cov.title} | {cov.type} | {where} |"
            )
        lines += ["", "⚠ = covered only by combining partial coverage from multiple policies — verify the pieces together are complete.", ""]

    # ------------------------------------------------------- per-policy detail
    lines += ["## Per-Policy Detail", ""]
    for name, analysis in result.policies.items():
        lines += [f"### {name}", "", analysis.policy_summary, ""]
        if analysis.topics:
            lines += [f"**Topics:** {', '.join(analysis.topics)}", ""]
        if analysis.citations_addressed:
            lines += ["| Citation | Coverage | Notes |", "|---|---|---|"]
            for m in analysis.citations_addressed:
                lines.append(f"| §{m.citation} | {m.coverage} | {m.notes} |")
            lines += [""]
        else:
            lines += ["*No HIPAA requirements mapped to this document.*", ""]
        if analysis.internal_issues:
            lines += ["**Internal issues flagged:**", ""]
            lines += [f"- {issue}" for issue in analysis.internal_issues]
            lines += [""]

    lines += [
        "---",
        "",
        "*This report was generated by automated analysis and is an aid to — not a substitute for — "
        "review by a qualified HIPAA compliance professional or counsel.*",
        "",
    ]
    return "\n".join(lines)
