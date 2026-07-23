import unittest

from src.config import settings
from src import llm as llm_module
from src.models import EmailInput
from src.workflow.graph import run_analysis


class EvidenceFusionTest(unittest.TestCase):
    def setUp(self):
        settings.llm.api_key = ""
        llm_module.llm_client = None

    def test_run_analysis_should_return_structured_evidence_items(self):
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
        self.assertIn("evidence_items", report)
        self.assertGreaterEqual(len(report["evidence_items"]), 3)

        evidence_types = {item["type"] for item in report["evidence_items"]}
        self.assertIn("semantic", evidence_types)
        self.assertIn("detection", evidence_types)

        for item in report["evidence_items"]:
            self.assertIn("type", item)
            self.assertIn("source", item)
            self.assertIn("weight", item)
            self.assertIn("confidence", item)
            self.assertIn("reason", item)

    def test_evidence_items_should_be_weighted_and_cumulative(self):
        email = EmailInput(
            subject="付款审批确认",
            sender="finance@unknown-domain.xyz",
            body="请确认附件中的付款单据并立即处理。",
            urls=["https://verify-account.secure-click.link/confirm"],
            headers={"spf": "none", "dkim": "fail", "dmarc": "none"},
            has_attachment=True,
        )

        report = run_analysis(email)
        evidence_items = report["evidence_items"]

        weights = [item["weight"] for item in evidence_items]
        self.assertEqual(sum(weights), 100)

        types = {item["type"] for item in evidence_items}
        self.assertIn("header_validation", types)
        self.assertIn("attachment", types)


if __name__ == "__main__":
    unittest.main()
