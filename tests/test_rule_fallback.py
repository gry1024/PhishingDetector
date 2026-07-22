import unittest

from src.config import settings
from src import llm as llm_module
from src.models import EmailInput
from src.workflow.graph import run_analysis


class RuleFallbackTest(unittest.TestCase):
    def test_run_analysis_should_fallback_when_llm_unavailable(self):
        settings.llm.api_key = ""
        llm_module.llm_client = None
        email = EmailInput(
            subject="紧急验证您的账户",
            sender="security@bank-alert.com",
            body="请在24小时内点击此链接验证账户。",
            urls=["http://192.168.1.100/verify"],
            headers={"spf": "none", "dkim": "fail", "dmarc": "none"},
            has_attachment=False,
        )

        report = run_analysis(email)
        self.assertNotIn("error", report)
        self.assertIn("risk_score", report)
        self.assertIn("risk_level", report)

    def test_detection_should_surface_header_and_attachment_evidence(self):
        settings.llm.api_key = ""
        llm_module.llm_client = None
        email = EmailInput(
            subject="付款审批确认",
            sender="finance@unknown-domain.xyz",
            body="请确认附件中的付款单据并立即处理。",
            urls=["https://verify-account.secure-click.link/confirm"],
            headers={"spf": "none", "dkim": "fail", "dmarc": "none"},
            has_attachment=True,
        )

        report = run_analysis(email)
        flags = report["detection"]["content_flags"]
        self.assertIn("email_header_validation_failed", flags)
        self.assertIn("possible_attachment_scam", flags)


if __name__ == "__main__":
    unittest.main()
