"""Web GUI tests with the analysis pipeline mocked (no API key needed)."""

import io
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hipaa_analyzer.aggregator import aggregate_coverage
from hipaa_analyzer.knowledge_base import KnowledgeBase
from hipaa_analyzer.models import (
    AnalysisResult,
    CitationMapping,
    Contradiction,
    PolicyAnalysis,
)


def fake_result() -> AnalysisResult:
    kb = KnowledgeBase.load()
    analyses = {
        "security.md": PolicyAnalysis(
            policy_summary="Security policy.",
            topics=["access control"],
            citations_addressed=[
                CitationMapping(
                    citation="164.312(a)(2)(i)",
                    coverage="full",
                    evidence="unique user ID",
                    notes="Fully specified.",
                ),
                CitationMapping(
                    citation="164.524",
                    coverage="partial",
                    evidence="records on request",
                    notes="No timeline stated.",
                ),
            ],
            internal_issues=["Retention stated as 3 years; HIPAA requires 6."],
        ),
        "privacy.md": PolicyAnalysis(
            policy_summary="Privacy policy.",
            topics=["patient rights"],
            citations_addressed=[
                CitationMapping(
                    citation="164.524",
                    coverage="partial",
                    evidence="30 day fulfillment",
                    notes="Timeline only.",
                ),
            ],
            internal_issues=[],
        ),
    }
    return AnalysisResult(
        policies=analyses,
        coverage=aggregate_coverage(kb, analyses),
        contradictions=[
            Contradiction(
                policy_a="security.md",
                policy_b="privacy.md",
                topic="Session timeout",
                description="Conflicting timeout values.",
                excerpt_a="15 minutes",
                excerpt_b="5 minutes",
                severity="high",
                recommendation="Standardize on one value.",
            )
        ],
        knowledge_base_version=kb.version,
        model="claude-opus-4-8",
    )


class WebAppTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch(
            "hipaa_analyzer.web.app.run_analysis", side_effect=lambda *a, **k: fake_result()
        )
        self.mock_run = patcher.start()
        self.addCleanup(patcher.stop)

        from hipaa_analyzer.web.app import create_app

        app = create_app()
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _submit(self, **overrides):
        data = {
            "org_name": "Test Clinic",
            "org_type": "Hospital",
            "contact_name": "Jane",
            "contact_email": "jane@example.com",
            "api_key": "sk-ant-test",
            "model": "claude-opus-4-8",
            "policies": [
                (io.BytesIO(b"# Security Policy\ncontent here"), "security.md"),
                (io.BytesIO(b"# Privacy Policy\ncontent here"), "privacy.md"),
            ],
        }
        data.update(overrides)
        return self.client.post(
            "/analyze", data=data, content_type="multipart/form-data", follow_redirects=False
        )

    def _wait_done(self, job_url: str, timeout: float = 5.0) -> None:
        job_id = job_url.rstrip("/").split("/")[-1]
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.client.get(f"/api/job/{job_id}").get_json()
            if status["status"] in ("done", "error"):
                self.assertEqual(status["status"], "done", status.get("error"))
                return
            time.sleep(0.05)
        self.fail("job did not finish in time")

    def test_index_renders(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Run a compliance analysis", r.data)

    def test_upload_analyze_and_results(self):
        r = self._submit()
        self.assertEqual(r.status_code, 302)
        job_url = r.headers["Location"]
        self._wait_done(job_url)

        job_id = job_url.rstrip("/").split("/")[-1]
        page = self.client.get(f"/job/{job_id}/results")
        self.assertEqual(page.status_code, 200)
        html = page.data.decode()
        for expected in [
            "Test Clinic",
            "Missing requirements",
            "Partially addressed",
            "Contradictions between policies",
            "Session timeout",
            "Full coverage matrix",
            "security.md",
            "Internal issues",
        ]:
            self.assertIn(expected, html)

        # downloads exist
        self.assertEqual(self.client.get(f"/job/{job_id}/download/report").status_code, 200)
        self.assertEqual(self.client.get(f"/job/{job_id}/download/json").status_code, 200)

    def test_rejects_no_files(self):
        r = self._submit(policies=[])
        # redirected back to index with a flash message
        self.assertEqual(r.status_code, 302)
        self.assertIn("/", r.headers["Location"])

    def test_rejects_unsupported_type(self):
        r = self._submit(policies=[(io.BytesIO(b"binary"), "malware.exe")])
        self.assertEqual(r.status_code, 302)
        follow = self.client.get(r.headers["Location"])
        self.assertIn(b"supported", follow.data)


if __name__ == "__main__":
    unittest.main()
