# HIPAA Policy Compliance Analyzer

Ingests a hospital's or practice's policies and procedures, cross-references them against the **HIPAA Privacy Rule, Security Rule, and Breach Notification Rule**, and produces a gap-analysis report that shows:

- **What's missing** — every HIPAA requirement not addressed by any policy, organized by rule.
- **What's partial** — requirements that are only superficially or incompletely addressed, with an explanation of what's missing.
- **Split coverage** — HIPAA doesn't require a 1:1 mapping between regulations and policies. The analyzer understands that one policy may cover part of a requirement and another policy the rest; coverage is aggregated across the whole policy set, and the report shows exactly which policies combine to satisfy each requirement (flagged for human verification).
- **Contradictions** — statements in different policies that conflict with each other (e.g., two different session-timeout values, conflicting retention periods, conflicting responsible parties), with verbatim excerpts, severity, and a reconciliation recommendation.
- **Internal issues** — statements inside a single policy that conflict with HIPAA itself (e.g., a 3-year retention period where HIPAA requires 6).

Analysis is powered by the Claude API (`claude-opus-4-8` by default) with structured outputs, so results are validated JSON — every cited regulation is checked against the built-in knowledge base and hallucinated citations are dropped.

## The regulation knowledge base

`hipaa_analyzer/data/hipaa_regulations.json` contains ~90 requirement entries covering:

| Rule | Coverage |
|---|---|
| **Security Rule** (45 CFR §164.302–318) | All administrative, physical, and technical safeguard standards and implementation specifications (required *and* addressable), organizational requirements, and documentation requirements |
| **Privacy Rule** (45 CFR §164.500–534) | Uses and disclosures (TPO, authorizations, minimum necessary, §164.510/512 permissions, de-identification, verification), individual rights (NPP, access, amendment, accounting, restrictions, confidential communications), and §164.530 administrative requirements |
| **Breach Notification Rule** (45 CFR §164.400–414) | Breach definition and risk assessment, individual/media/HHS notification, business associate notification, burden of proof |

You can supply your own knowledge base with `--kb path/to/custom.json` (same schema) — useful for adding state-law requirements or organization-specific standards.

## Installation

```bash
pip install -r requirements.txt

# optional, for .docx / .pdf policies:
pip install python-docx pypdf

export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage — Web GUI

```bash
python -m hipaa_analyzer.web            # then open http://127.0.0.1:5000/
```

The GUI lets you:

1. **Enter the organization's info** — name, type (hospital, practice, health plan, …), and contact person.
2. **Upload policies** — drag-and-drop or file picker, any mix of `.md`, `.txt`, `.docx`, `.pdf`.
3. **Provide the API key** — entered per-run in the form (held in memory only, never written to disk), or omitted if `ANTHROPIC_API_KEY` is set in the server environment.
4. **Watch progress** — a live status page updates as each policy is analyzed.
5. **Browse results** — a dashboard with coverage stat tiles, a coverage bar, missing/partial requirement tables grouped by rule, combined-coverage verification list, contradictions ordered by severity with excerpts and recommendations, the full coverage matrix, and per-policy detail — plus download buttons for the Markdown report and raw JSON.

Options: `python -m hipaa_analyzer.web --host 0.0.0.0 --port 8080` to serve on your network. Jobs live for the duration of the server process; the report and JSON are also written to the job's temp directory.

> Note: uploaded policies are sent to the Anthropic API for analysis. Policy documents are generally not PHI, but review your organization's vendor/data-handling requirements before uploading anything sensitive.

## Usage — CLI

Put all of the organization's policies in one directory (`.md`, `.txt`, `.docx`, `.pdf`), then:

```bash
python -m hipaa_analyzer analyze ./policies -o gap_report.md --org "Example Health"
```

Options:

| Flag | Purpose |
|---|---|
| `-o / --output` | Markdown report path (default `hipaa_gap_report.md`) |
| `--json results.json` | Also write the raw structured results as JSON |
| `--org "Name"` | Organization name in the report title |
| `--model` | Claude model (default `claude-opus-4-8`) |
| `--skip-contradictions` | Skip the cross-policy contradiction scan |
| `--kb custom.json` | Use a custom regulation knowledge base |

To inspect the built-in requirement list:

```bash
python -m hipaa_analyzer list-requirements            # all
python -m hipaa_analyzer list-requirements --rule security
```

### Try it on the samples

`examples/sample_policies/` contains three realistic sample policies with deliberate gaps (no contingency plan, no breach-notification procedures, no BAA policy) and a deliberate contradiction (15-minute vs 5-minute workstation lock):

```bash
python -m hipaa_analyzer analyze examples/sample_policies -o sample_report.md
```

## How it works

1. **Ingestion** — all supported documents in the directory are loaded and text-extracted.
2. **Per-policy mapping** — each policy is analyzed by Claude against the full requirement list (which is prompt-cached, so a large policy set only pays for the reference text once). The model returns a structured list of `(citation, full|partial, evidence quote, notes)` mappings plus internal-issue flags. Citations are validated against the knowledge base.
3. **Deterministic aggregation** — coverage is combined across policies in code:
   - `covered` — at least one policy fully satisfies the requirement, **or** two or more policies each partially address it (flagged ⚠ *combined coverage* for human verification);
   - `partial` — exactly one policy addresses it, incompletely;
   - `missing` — no policy addresses it.
4. **Contradiction scan** — the entire policy set is sent in a single request (the 1M-token context window comfortably holds a typical policy manual) so the model can compare every pair of documents directly and report genuine conflicts with verbatim excerpts.
5. **Report** — a Markdown report with executive summary, gap list, partial-coverage detail, contradictions ordered by severity, a full coverage matrix, and per-policy detail. Optionally raw JSON for downstream tooling.

## Tests

Offline tests (no API key needed) cover the knowledge base, ingestion, aggregation logic, and report rendering:

```bash
python -m unittest discover tests -v
```

## Disclaimer

This tool is an aid to compliance review, not a substitute for it. Findings should be verified by a qualified HIPAA compliance professional or counsel.
