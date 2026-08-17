"""
检测工作流 — Orchestrator 模式
=================================
主编排 Agent（Orchestrator）真正调用子 Agent，而非固定流水线。

架构变化：
- 旧模式：4 Agent 串行流水线（semantic → detector → risk → response）
- 新模式：Orchestrator 编排器决策调用子 Agent，思考过程作为叙事输出

Orchestrator 的职责：
1. 分析邮件特征，制定检测策略（Phase 1）
2. 依次调用子 Agent，每次调用前叙述决策逻辑（Phase 2）
3. 综合所有结果生成报告（Phase 3）

事件协议：
- orchestrator_start: 编排器启动
- orchestrator_thinking: 编排器思考叙事（自然语言流式输出）
- agent_call: 编排器调用子 Agent
- agent_result: 子 Agent 返回结果
- report: 最终报告
- orchestrator_done: 编排器完成

子 Agent 的事件（thinking/tool_call/sub_step/llm_chunk）仍然通过同一 callback 推送，
前端将它们渲染在对应的子 Agent 调用块内。
"""

import logging
from typing import Callable, Optional

from src.models import EmailInput
from src.agents.orchestrator import OrchestratorAgent

logger = logging.getLogger(__name__)

# Agent 元数据（保留兼容性，供 API 端点返回）
AGENT_PIPELINE = [
    {"id": "sender_profiler", "name": "发件人画像分析", "icon": "👤", "index": 0},
    {"id": "header_forensics", "name": "邮件头取证分析", "icon": "📨", "index": 1},
    {"id": "semantic", "name": "语义意图分析", "icon": "🧠", "index": 2},
    {"id": "threat_intel", "name": "威胁情报关联", "icon": "🛰️", "index": 3},
    {"id": "detector", "name": "多维关联检测", "icon": "🔍", "index": 4},
    {"id": "risk", "name": "风险研判", "icon": "⚖️", "index": 5},
    {"id": "response", "name": "响应处置", "icon": "🛡️", "index": 6},
]

AGENT_PIPELINE_BY_ID = {item["id"]: item for item in AGENT_PIPELINE}


def run_analysis(
    email: EmailInput,
    callback: Callable[[dict], None] = None,
    selected_steps: Optional[list[str]] = None,
    execution_mode: str = "serial",
    skip_web_search: bool = False,
):
    """
    执行完整的邮件检测工作流（Orchestrator 模式）

    Args:
        email: 待分析的邮件
        callback: 事件回调函数
        selected_steps: 用户选择的子 Agent 步骤（可选）
        execution_mode: 执行模式（serial/cluster，Orchestrator 模式下始终串行）
        skip_web_search: 为 True 时 threat_intel 跳过全部联网检索（评测场景提速）

    Returns:
        完整的分析报告字典
    """
    orchestrator = OrchestratorAgent()

    try:
        report = orchestrator.analyze(
            email,
            callback=callback,
            selected_steps=selected_steps,
            skip_web_search=skip_web_search,
        )
    except Exception as e:
        logger.error(f"编排器执行失败: {e}", exc_info=True)
        if callback:
            callback({"type": "error", "data": {"message": str(e)}})
        return {"error": str(e)}

    return report
