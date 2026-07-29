import unittest
from unittest.mock import patch

from src.models import (
    EmailInput,
    SemanticResult,
    DetectionResult,
    RiskResult,
    ResponseResult,
)
from src.workflow.graph import run_analysis


class _SemanticStub:
    def analyze(self, email, callback=None, **kwargs):
        return {
            "semantic": SemanticResult(
                intent="suspicious",
                persuasion_techniques=["urgency"],
                explanation="semantic stub",
                confidence=0.8,
            )
        }


class _DetectorStub:
    def analyze(self, email, callback=None, semantic_result=None, **kwargs):
        return {
            "detection": DetectionResult(
                sender_score=0.6,
                sender_analysis="detector stub",
                url_score=0.4,
                url_analysis="detector stub",
                content_flags=["suspicious_link"],
                explanation="detector stub",
            )
        }


class _RiskStub:
    def analyze(self, email, callback=None, semantic_result=None, detection_result=None, **kwargs):
        return {
            "risk": RiskResult(
                risk_score=70,
                risk_level="high",
                attack_techniques=["T1566.002"],
                explanation="risk stub",
            ),
            "is_phishing": True,
        }


class _ResponseStub:
    def analyze(self, email, callback=None, semantic_result=None, detection_result=None, risk_result=None, **kwargs):
        return {
            "response": ResponseResult(
                action="isolate",
                alert_message="response stub",
                trace_report="response stub",
                recommendation="response stub",
            )
        }


class SelectedStepsTest(unittest.TestCase):
    @patch("src.workflow.graph.SemanticAgent", return_value=_SemanticStub())
    @patch("src.workflow.graph.DetectorAgent", return_value=_DetectorStub())
    @patch("src.workflow.graph.RiskAgent", return_value=_RiskStub())
    @patch("src.workflow.graph.ResponseAgent", return_value=_ResponseStub())
    def test_should_only_run_selected_steps(self, *_mocks):
        email = EmailInput(body="test")
        events = []

        def cb(event):
            events.append(event)

        report = run_analysis(email, callback=cb, selected_steps=["semantic", "risk"])

        self.assertNotIn("error", report)
        self.assertTrue(report["risk"])  # risk should exist
        self.assertEqual(report["response"], {})  # response should not run

        started = [e["data"].get("step_id") for e in events if e["type"] == "agent_start"]
        self.assertEqual(started, ["semantic", "risk"])

    @patch("src.workflow.graph.SemanticAgent", return_value=_SemanticStub())
    @patch("src.workflow.graph.DetectorAgent", return_value=_DetectorStub())
    @patch("src.workflow.graph.RiskAgent", return_value=_RiskStub())
    @patch("src.workflow.graph.ResponseAgent", return_value=_ResponseStub())
    def test_should_insert_risk_before_response_when_missing(self, *_mocks):
        email = EmailInput(body="test")
        events = []

        def cb(event):
            events.append(event)

        run_analysis(email, callback=cb, selected_steps=["detector", "semantic", "response"])

        started = [e["data"].get("step_id") for e in events if e["type"] == "agent_start"]
        self.assertEqual(started, ["semantic", "detector", "risk", "response"])

        # 验证会输出自动补齐提示，便于前端解释执行行为
        hints = [
            e["data"].get("chunk", "")
            for e in events
            if e["type"] == "thinking" and e["data"].get("agent") == "系统"
        ]
        self.assertTrue(any("自动补齐 risk" in msg for msg in hints))


if __name__ == "__main__":
    unittest.main()
