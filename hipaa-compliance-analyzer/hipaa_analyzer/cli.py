"""Command-line interface.

Usage:
    python -m hipaa_analyzer analyze ./policies -o report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .aggregator import coverage_stats
from .analyzer import DEFAULT_MODEL
from .ingestion import IngestionError, load_directory
from .knowledge_base import KnowledgeBase
from .pipeline import run_analysis
from .report import render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hipaa-analyzer",
        description="Analyze an organization's policies and procedures against HIPAA "
        "Privacy, Security, and Breach Notification Rule requirements.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a directory of policy documents")
    analyze.add_argument("directory", help="Directory containing policy documents (.txt, .md, .docx, .pdf)")
    analyze.add_argument("-o", "--output", default="hipaa_gap_report.md", help="Markdown report output path")
    analyze.add_argument("--json", dest="json_output", default=None, help="Also write raw results as JSON to this path")
    analyze.add_argument("--org", default=None, help="Organization name for the report title")
    analyze.add_argument("--model", default=DEFAULT_MODEL, help=f"Claude model to use (default: {DEFAULT_MODEL})")
    analyze.add_argument("--skip-contradictions", action="store_true", help="Skip the cross-policy contradiction scan")
    analyze.add_argument("--kb", default=None, help="Path to a custom regulation knowledge base JSON")

    list_reqs = sub.add_parser("list-requirements", help="Print the built-in HIPAA requirement knowledge base")
    list_reqs.add_argument("--rule", choices=["privacy", "security", "breach"], default=None)
    list_reqs.add_argument("--kb", default=None, help="Path to a custom regulation knowledge base JSON")

    return parser


def cmd_list_requirements(args: argparse.Namespace) -> int:
    kb = KnowledgeBase.load(args.kb)
    reqs = kb.by_rule(args.rule) if args.rule else kb.requirements
    for r in reqs:
        print(f"§{r.citation:<26} [{r.rule}/{r.type}] {r.title}")
    print(f"\n{len(reqs)} requirements (knowledge base v{kb.version})")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    kb = KnowledgeBase.load(args.kb)

    try:
        docs = load_directory(args.directory)
    except IngestionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"Loaded {len(docs)} policy document(s):")
    for d in docs:
        note = " (truncated — exceeded size limit)" if d.truncated else ""
        print(f"  - {d.name} ({len(d.text):,} chars){note}")

    result = run_analysis(
        docs,
        kb=kb,
        model=args.model,
        skip_contradictions=args.skip_contradictions,
        progress=lambda msg: print(f"... {msg}"),
    )

    report_md = render_markdown(result, org_name=args.org)
    Path(args.output).write_text(report_md, encoding="utf-8")
    print(f"\nReport written to {args.output}")

    if args.json_output:
        Path(args.json_output).write_text(
            json.dumps(result.model_dump(), indent=2), encoding="utf-8"
        )
        print(f"Raw results written to {args.json_output}")

    stats = coverage_stats(result.coverage)
    print(
        f"\nSummary: {stats['covered']} covered / {stats['partial']} partial / "
        f"{stats['missing']} missing of {stats['total']} requirements; "
        f"{len(result.contradictions)} contradiction(s)."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-requirements":
        return cmd_list_requirements(args)
    return cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
