"""
execution_mode 参数兼容性测试（Orchestrator 架构版）
======================================================
execution_mode 参数保留在 run_analysis 接口中，但 Orchestrator 模式下始终串行执行
（见 src/workflow/graph.py 注释）。

本文件验证：
- cluster 模式不会报错，且子 Agent 严格按 agent_call → agent_result 串行交替推进
- cluster 与 serial 两种模式产生完全一致的子 Agent 调用序列

说明：旧版断言"cluster 比 serial 快"（基于已移除的并行流水线架构），
该前提在 Orchestrator 架构下不成立，故改为行为等价性断言。
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
    }
    patched = {}
    for key, stub_cls in stubs.items():
        meta = dict(OrchestratorAgent.SUB_AGENTS[key])
        meta["agent_class"] = stub_cls
        patched[key] = meta
    return patch.dict(OrchestratorAgent.SUB_AGENTS, patched)(func)


# selected_steps=["semantic", "detector", "risk"] 的期望调用序列：
# threat_intel 由编排器强制纳入（插在 detector 前）
EXPECTED_SEQUENCE = ["semantic", "threat_intel", "detector", "risk"]


class ClusterExecutionModeTest(unittest.TestCase):
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
    def _run(email, execution_mode):
        events = []
        report = run_analysis(
            email,
            callback=events.append,
            selected_steps=["semantic", "detector", "risk"],
            execution_mode=execution_mode,
        )
        return report, events

    @_with_stubbed_agents
    def test_cluster_mode_should_execute_serially_with_call_result_pairs(self):
        email = EmailInput(body="test")

        report, events = self._run(email, "cluster")

        self.assertNotIn("error", report)

        # 严格串行：每个 agent_call 之后紧跟同 agent 的 agent_result，再进入下一个调用
        call_result_pairs = [
            (e["type"], e["data"].get("agent_key"))
            for e in events
            if e["type"] in {"agent_call", "agent_result"}
        ]
        expected_pairs = []
        for agent_key in EXPECTED_SEQUENCE:
            expected_pairs.append(("agent_call", agent_key))
            expected_pairs.append(("agent_result", agent_key))
        self.assertEqual(call_result_pairs, expected_pairs)

    @_with_stubbed_agents
    def test_cluster_and_serial_should_produce_identical_call_sequence(self):
        email = EmailInput(body="test")

        report_cluster, events_cluster = self._run(email, "cluster")
        report_serial, events_serial = self._run(email, "serial")

        self.assertNotIn("error", report_cluster)
        self.assertNotIn("error", report_serial)

        sequence_cluster = [
            e["data"].get("agent_key") for e in events_cluster if e["type"] == "agent_call"
        ]
        sequence_serial = [
            e["data"].get("agent_key") for e in events_serial if e["type"] == "agent_call"
        ]
        self.assertEqual(sequence_cluster, EXPECTED_SEQUENCE)
        self.assertEqual(sequence_cluster, sequence_serial)
        # 两模式产出一致的最终结论
        self.assertEqual(report_cluster["risk_level"], report_serial["risk_level"])


if __name__ == "__main__":
    unittest.main()
