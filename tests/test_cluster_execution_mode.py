import time
import unittest
from unittest.mock import patch

from src.models import EmailInput, SemanticResult, DetectionResult, RiskResult, ResponseResult
from src.workflow.graph import run_analysis


class _SemanticSlowStub:
    def analyze(self, email, callback=None, **kwargs):
        time.sleep(0.2)
        return {
            "semantic": SemanticResult(
                intent="suspicious",
                persuasion_techniques=["urgency"],
                explanation="semantic",
                confidence=0.8,
            )
        }


class _DetectorSlowStub:
    def analyze(self, email, callback=None, semantic_result=None, **kwargs):
        time.sleep(0.2)
        return {
            "detection": DetectionResult(
                sender_score=0.6,
                sender_analysis="detector",
                url_score=0.4,
                url_analysis="detector",
                content_flags=["suspicious_link"],
                explanation="detector",
            )
        }


class _RiskStub:
    def analyze(self, email, callback=None, semantic_result=None, detection_result=None, **kwargs):
        return {
            "risk": RiskResult(
                risk_score=70,
                risk_level="high",
                attack_techniques=["T1566.002"],
                explanation="risk",
            ),
            "is_phishing": True,
        }


class _ResponseStub:
    def analyze(self, email, callback=None, semantic_result=None, detection_result=None, risk_result=None, **kwargs):
        return {
            "response": ResponseResult(
                action="isolate",
                alert_message="response",
                trace_report="response",
                recommendation="response",
            )
        }


class ClusterExecutionModeTest(unittest.TestCase):
    @patch("src.workflow.graph.SemanticAgent", return_value=_SemanticSlowStub())
    @patch("src.workflow.graph.DetectorAgent", return_value=_DetectorSlowStub())
    @patch("src.workflow.graph.RiskAgent", return_value=_RiskStub())
    @patch("src.workflow.graph.ResponseAgent", return_value=_ResponseStub())
    def test_cluster_mode_should_parallel_semantic_and_detector(self, *_mocks):
        email = EmailInput(body="test")

        t1 = time.perf_counter()
        run_analysis(
            email,
            selected_steps=["semantic", "detector", "risk"],
            execution_mode="cluster",
        )
        cluster_elapsed = time.perf_counter() - t1

        t2 = time.perf_counter()
        run_analysis(
            email,
            selected_steps=["semantic", "detector", "risk"],
            execution_mode="serial",
        )
        serial_elapsed = time.perf_counter() - t2

        self.assertLess(cluster_elapsed, serial_elapsed)


if __name__ == "__main__":
    unittest.main()
