"""Flask application: upload policies, run the analysis, browse results."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from ..aggregator import coverage_stats
from ..analyzer import DEFAULT_MODEL
from ..ingestion import SUPPORTED_EXTENSIONS, IngestionError, load_document
from ..knowledge_base import KnowledgeBase
from ..pipeline import run_analysis
from ..report import render_markdown
from .jobs import Job, JobManager, OrgInfo

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB per request

_RULE_NAMES = {
    "privacy": "Privacy Rule",
    "security": "Security Rule",
    "breach": "Breach Notification Rule",
}


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.secret_key = os.environ.get("HIPAA_ANALYZER_SECRET", os.urandom(24).hex())

    jobs = JobManager()
    upload_root = Path(tempfile.mkdtemp(prefix="hipaa_analyzer_"))
    kb = KnowledgeBase.load()

    # ------------------------------------------------------------- helpers

    def run_job(job: Job, model: str, api_key: str | None, skip_contradictions: bool):
        docs = []
        for name in job.files:
            jobs.set_message(job, f"Reading {name}")
            docs.append(load_document(job.directory / name))
        result = run_analysis(
            docs,
            kb=kb,
            model=model,
            api_key=api_key,
            skip_contradictions=skip_contradictions,
            progress=lambda msg: jobs.set_message(job, msg),
        )
        job.result = result
        job.report_md = render_markdown(result, org_name=job.org.name or None)
        (job.directory / "report.md").write_text(job.report_md, encoding="utf-8")
        (job.directory / "results.json").write_text(
            json.dumps(result.model_dump(), indent=2), encoding="utf-8"
        )

    def get_job_or_404(job_id: str) -> Job:
        job = jobs.get(job_id)
        if job is None:
            abort(404)
        return job

    # -------------------------------------------------------------- routes

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            default_model=DEFAULT_MODEL,
            has_env_key=bool(os.environ.get("ANTHROPIC_API_KEY")),
            supported=sorted(SUPPORTED_EXTENSIONS),
            kb_count=len(kb.requirements),
            recent_jobs=jobs.all()[:8],
        )

    @app.route("/analyze", methods=["POST"])
    def analyze():
        org = OrgInfo(
            name=request.form.get("org_name", "").strip(),
            org_type=request.form.get("org_type", "").strip(),
            contact_name=request.form.get("contact_name", "").strip(),
            contact_email=request.form.get("contact_email", "").strip(),
        )
        api_key = request.form.get("api_key", "").strip() or None
        model = request.form.get("model", "").strip() or DEFAULT_MODEL
        skip_contradictions = request.form.get("skip_contradictions") == "on"

        if not api_key and not os.environ.get("ANTHROPIC_API_KEY"):
            flash("An Anthropic API key is required (none found in the environment).")
            return redirect(url_for("index"))

        uploads = [f for f in request.files.getlist("policies") if f and f.filename]
        if not uploads:
            flash("Please upload at least one policy document.")
            return redirect(url_for("index"))

        job_dir = Path(tempfile.mkdtemp(prefix="job_", dir=upload_root))
        saved: list[str] = []
        for f in uploads:
            name = secure_filename(f.filename or "")
            if not name or Path(name).suffix.lower() not in SUPPORTED_EXTENSIONS:
                flash(f"Skipped unsupported file: {f.filename}")
                continue
            f.save(job_dir / name)
            saved.append(name)
        if not saved:
            flash("None of the uploaded files are a supported type.")
            return redirect(url_for("index"))

        # Validate readability up front so obvious problems fail fast.
        for name in saved:
            try:
                load_document(job_dir / name)
            except IngestionError as e:
                flash(str(e))
                return redirect(url_for("index"))

        job = jobs.create(org, job_dir, saved)
        jobs.run_in_background(
            job, lambda j: run_job(j, model, api_key, skip_contradictions)
        )
        return redirect(url_for("progress", job_id=job.id))

    @app.route("/job/<job_id>")
    def progress(job_id: str):
        job = get_job_or_404(job_id)
        if job.status == "done":
            return redirect(url_for("results", job_id=job.id))
        return render_template("progress.html", job=job)

    @app.route("/api/job/<job_id>")
    def job_status(job_id: str):
        job = get_job_or_404(job_id)
        return jsonify(
            {"id": job.id, "status": job.status, "message": job.message, "error": job.error}
        )

    @app.route("/job/<job_id>/results")
    def results(job_id: str):
        job = get_job_or_404(job_id)
        if job.status != "done" or job.result is None:
            return redirect(url_for("progress", job_id=job.id))
        result = job.result
        stats = coverage_stats(result.coverage)
        missing = [c for c in result.coverage if c.status == "missing"]
        partial = [c for c in result.coverage if c.status == "partial"]
        combined = [
            c
            for c in result.coverage
            if c.status == "covered" and not any(x.coverage == "full" for x in c.contributions)
        ]
        sev_order = {"high": 0, "medium": 1, "low": 2}
        contradictions = sorted(result.contradictions, key=lambda c: sev_order[c.severity])
        return render_template(
            "results.html",
            job=job,
            result=result,
            stats=stats,
            missing=missing,
            partial=partial,
            combined=combined,
            contradictions=contradictions,
            rule_names=_RULE_NAMES,
        )

    @app.route("/job/<job_id>/download/<kind>")
    def download(job_id: str, kind: str):
        job = get_job_or_404(job_id)
        if kind == "report":
            path, name = job.directory / "report.md", "hipaa_gap_report.md"
        elif kind == "json":
            path, name = job.directory / "results.json", "hipaa_results.json"
        else:
            abort(404)
        if not path.exists():
            abort(404)
        return send_file(path, as_attachment=True, download_name=name)

    return app
