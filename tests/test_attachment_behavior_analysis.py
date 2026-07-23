import unittest

from src.config import settings
from src import llm as llm_module
from src.models import EmailInput
from src.workflow.graph import run_analysis


class AttachmentBehaviorAnalysisTest(unittest.TestCase):
    def setUp(self):
        settings.llm.api_key = ""
        llm_module.llm_client = None

    def test_attachment_analysis_should_surface_suspicious_attachment_signal(self):
        email = EmailInput(
            subject="付款单据请查收",
            sender="finance@support-verify.xyz",
            body="请在附件查看付款单据，双击后请勿打开外部链接。",
            urls=["https://verify-account.secure-click.link/confirm"],
            headers={"spf": "none", "dkim": "fail", "dmarc": "none"},
            has_attachment=True,
        )

        report = run_analysis(email)
        flags = report["detection"]["content_flags"]
        self.assertIn("possible_attachment_scam", flags)

    def test_behavior_anomaly_should_emit_structured_evidence(self):
        email = EmailInput(
            subject="紧急：请立即验证账户",
            sender="security@quick-verify.online",
            body="为了避免账户冻结，请立即点击链接完成安全验证并输入密码。",
            urls=["https://verify-account.secure-click.link/confirm"],
            headers={"spf": "none", "dkim": "fail", "dmarc": "none"},
            has_attachment=False,
        )

        report = run_analysis(email)
        evidence_items = report["evidence_items"]
        matches = [item for item in evidence_items if item["type"] == "behavior_anomaly"]
        self.assertTrue(matches, "expected behavior anomaly evidence item to exist")
        self.assertGreaterEqual(matches[0]["weight"], 5)


if __name__ == "__main__":
    unittest.main()
