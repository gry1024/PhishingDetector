"""
selected_steps 执行控制测试（Orchestrator 架构版）
====================================================
按 Orchestrator 新事件协议（agent_call / agent_result）验证：
- 用户自选步骤时只运行对应子 Agent（依赖自动补齐 + 威胁情报强制纳入）
- selected_steps 含 response 但缺 risk 时，自动在 response 前插入 risk

说明：旧版断言 agent_start/thinking(agent=系统) 事件，已随流水线架构移除；
本文件改为断言 agent_call 事件序列与报告结构。
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src.config import settings
from src import llm as llm_module
from src.agents.orchestrator import OrchestratorAgent
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


class _ThreatIntelStub:
    """威胁情报桩：替代含联网检索的真实 Agent，保证测试快速且可重复。"""

    def analyze(self, email, callback=None, **kwargs):
        return {
            "threat_intel": SimpleNamespace(
                ioc_count=0,
                ioc_list=[],
                threat_patterns=[],
                threat_score=0,
                attack_techniques=[],
                explanation="threat intel stub",
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


def _with_stubbed_agents(func):
    """装饰器：把会被调用的子 Agent 替换为桩（作用于 SUB_AGENTS 注册表）。

    注意必须替换 SUB_AGENTS 内的 agent_class 引用——SUB_AGENTS 在
    OrchestratorAgent 类定义时已捕获原始类对象，直接 patch 模块级类名
    不会影响注册表，真实子 Agent（含 threat_intel 联网检索）仍会被调用。
    """
    stubs = {
        "semantic": _SemanticStub,
        "threat_intel": _ThreatIntelStub,
        "detector": _DetectorStub,
        "risk": _RiskStub,
        "response": _ResponseStub,
    }
    patched = {}
    for key, stub_cls in stubs.items():
        meta = dict(OrchestratorAgent.SUB_AGENTS[key])
        meta["agent_class"] = stub_cls
        patched[key] = meta
    return patch.dict(OrchestratorAgent.SUB_AGENTS, patched)(func)


class SelectedStepsTest(unittest.TestCase):
    def setUp(self):
        # 强制 LLM 不可用，让 Orchestrator Phase 1 走规则兜底策略，避免真实 API 调用
        self._old_api_key = settings.llm.api_key
        self._old_client = llm_module.llm_client
        self._old_init_failed = llm_module._llm_init_failed
        settings.llm.api_key = ""
        llm_module.llm_client = None
        llm_module._llm_init_failed = False

    def tearDown(self):
        settings.llm.api_key = self._old_api_key
        llm_module.llm_client = self._old_client
        llm_module._llm_init_failed = self._old_init_failed

    @staticmethod
    def _agent_call_sequence(events):
        return [e["data"].get("agent_key") for e in events if e["type"] == "agent_call"]

    @_with_stubbed_agents
    def test_should_only_run_selected_steps(self):
        email = EmailInput(body="test")
        events = []

        report = run_analysis(email, callback=events.append, selected_steps=["semantic", "risk"])

        self.assertNotIn("error", report)
        self.assertTrue(report["risk"])  # risk 应存在
        self.assertEqual(report["response"], {})  # response 不应运行

        # 依赖补齐：risk 依赖 detector；threat_intel 由编排器强制纳入（插在 detector 前）
        self.assertEqual(
            self._agent_call_sequence(events),
            ["semantic", "threat_intel", "detector", "risk"],
        )

        # 每个 agent_call 都应有对应的 agent_result
        results = [e["data"].get("agent_key") for e in events if e["type"] == "agent_result"]
        self.assertEqual(results, ["semantic", "threat_intel", "detector", "risk"])

    @_with_stubbed_agents
    def test_should_insert_risk_before_response_when_missing(self):
        email = EmailInput(body="test")
        events = []

        report = run_analysis(
            email,
            callback=events.append,
            selected_steps=["detector", "semantic", "response"],
        )

        self.assertNotIn("error", report)

        # response 依赖 risk，自动补齐后按流水线逻辑顺序执行；
        # threat_intel 由编排器强制纳入（插在 detector 前）
        sequence = self._agent_call_sequence(events)
        self.assertEqual(
            sequence,
            ["semantic", "threat_intel", "detector", "risk", "response"],
        )

        # 自动补齐的 risk 必须紧邻 response 之前
        self.assertEqual(sequence[sequence.index("response") - 1], "risk")
        self.assertTrue(report["risk"])
        self.assertTrue(report["response"])


if __name__ == "__main__":
    unittest.main()
