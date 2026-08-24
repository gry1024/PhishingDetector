import unittest

from src.config import settings
from src.agents.risk import RiskAgent
from src import llm as llm_module
from src.models import DetectionResult, EmailInput, SemanticResult
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
        self.assertIn("rule_score", report["risk"])
        self.assertIn("llm_score", report["risk"])
        self.assertIn("llm_participated", report["risk"])
        self.assertIn("score_gap", report["risk"])

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

    def test_risk_prompt_should_include_kb_hits(self):
        agent = RiskAgent()
        email = EmailInput(
            subject="电子发票待查收",
            sender="billing@example.com",
            body="请在浏览器中打开附件里的网页文件查看电子发票。",
        )
        semantic = SemanticResult(intent="suspicious", explanation="", persuasion_techniques=["urgency"])
        detection = DetectionResult(
            sender_analysis="",
            url_analysis="",
            explanation="",
            kb_hits=[{
                "title": "HTML 走私（HTML Smuggling）",
                "category": "攻击手法",
                "severity": "high",
                "score": 92,
                "matched_keywords": ["html"],
                "matched_semantic_terms": ["html_smuggling"],
                "summary": "利用网页文件绕过静态检测。",
                "recommendation": "优先人工复核。",
            }],
            kb_summary="HTML 走私（HTML Smuggling）(high,score=92)",
        )

        prompt = agent._build_prompt(email, semantic, detection, 42)

        self.assertIn("知识库命中", prompt)
        self.assertIn("HTML 走私", prompt)
        self.assertIn("html_smuggling", prompt)

    def test_fallback_should_not_fake_llm_score(self):
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
        risk = report["risk"]

        # 兜底不得伪造 LLM 参与度
        self.assertEqual(risk["llm_score"], 0)
        self.assertFalse(risk["llm_participated"])
        # 规则兜底专属增强：final = max(rule_score, 品类命中抬档)，只会向上抬
        self.assertGreaterEqual(risk["risk_score"], risk["rule_score"])
        # 该样本命中 ≥2 个强品类模式（中文凭证窃取/中文紧急施压），应被抬到 high 判定线以上
        self.assertGreaterEqual(risk["risk_score"], 61)
        self.assertEqual(report["is_phishing"], risk["risk_level"] in {"high", "critical"})


if __name__ == "__main__":
    unittest.main()
