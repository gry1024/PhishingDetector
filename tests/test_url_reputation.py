import unittest

from src.config import settings
from src import llm as llm_module
from src.models import EmailInput
from src.workflow.graph import run_analysis


class URLReputationTest(unittest.TestCase):
    def setUp(self):
        settings.llm.api_key = ""
        llm_module.llm_client = None

    def test_url_reputation_should_raise_reputation_evidence_on_known_phishing_domain(self):
        email = EmailInput(
            subject="紧急验证您的账户",
            sender="security@bank-alert.com",
            body="请在24小时内点击此链接验证账户。",
            urls=["http://192.168.1.100/verify"],
            headers={"spf": "none", "dkim": "fail", "dmarc": "none"},
            has_attachment=False,
        )

        report = run_analysis(email)
        evidence_items = report["evidence_items"]

        matches = [item for item in evidence_items if item["type"] == "url_reputation"]
        self.assertTrue(matches, "expected URL reputation evidence item to exist")
        self.assertGreaterEqual(matches[0]["weight"], 5)
        self.assertGreaterEqual(matches[0]["confidence"], 0.5)

    def test_url_reputation_failure_should_not_break_detection_flow(self):
        email = EmailInput(
            subject="付款审批确认",
            sender="finance@unknown-domain.xyz",
            body="请确认附件中的付款单据并立即处理。",
            urls=["https://verify-account.secure-click.link/confirm"],
            headers={"spf": "none", "dkim": "fail", "dmarc": "none"},
            has_attachment=True,
        )

        report = run_analysis(email)
        self.assertNotIn("error", report)
        self.assertIn("evidence_items", report)


if __name__ == "__main__":
    unittest.main()
