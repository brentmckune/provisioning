"""Loads the built-in HIPAA regulation knowledge base."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Optional


@dataclass(frozen=True)
class Requirement:
    citation: str
    rule: str  # "privacy" | "security" | "breach"
    category: str
    title: str
    type: str  # "required" | "addressable" | "standard"
    summary: str
    keywords: tuple[str, ...]

    @property
    def label(self) -> str:
        return f"45 CFR §{self.citation}"


class KnowledgeBase:
    def __init__(self, requirements: list[Requirement], version: str):
        self.requirements = requirements
        self.version = version
        self._by_citation = {r.citation: r for r in requirements}

    @classmethod
    def load(cls, path: Optional[str] = None) -> "KnowledgeBase":
        if path:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        else:
            ref = resources.files("hipaa_analyzer.data").joinpath("hipaa_regulations.json")
            raw = json.loads(ref.read_text(encoding="utf-8"))
        reqs = [
            Requirement(
                citation=r["citation"],
                rule=r["rule"],
                category=r["category"],
                title=r["title"],
                type=r["type"],
                summary=r["summary"],
                keywords=tuple(r.get("keywords", [])),
            )
            for r in raw["requirements"]
        ]
        return cls(reqs, raw.get("version", "unknown"))

    def get(self, citation: str) -> Optional[Requirement]:
        """Look up a requirement by citation, tolerating a '45 CFR' prefix or section symbol."""
        key = (
            citation.replace("45 CFR", "")
            .replace("§", "")
            .strip()
        )
        return self._by_citation.get(key)

    def citations(self) -> list[str]:
        return list(self._by_citation.keys())

    def by_rule(self, rule: str) -> list[Requirement]:
        return [r for r in self.requirements if r.rule == rule]

    def to_reference_text(self) -> str:
        """Render the knowledge base as compact text for use in a model prompt."""
        lines = []
        for r in self.requirements:
            lines.append(
                f"- {r.citation} [{r.rule}/{r.type}] {r.title}: {r.summary}"
            )
        return "\n".join(lines)
