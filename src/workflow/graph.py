"""
检测工作流
===========
串行执行 4 个 Agent，通过回调函数实时推送事件到前端。

流程：语义分析 → 多维检测 → 风险研判 → 响应处置

每个 Agent 执行期间，通过 callback 推送：
- agent_start: Agent 开始
- thinking: 思考过程（含 LLM 原始输出）
- tool_call: 工具调用结果
- agent_done: Agent 完成，附带结果摘要
- complete: 全流程完成
- error: 执行出错
"""

import logging
from typing import Callable, Optional

from src.models import EmailInput
from src.agents.semantic import SemanticAgent
from src.agents.detector import DetectorAgent
from src.agents.risk import RiskAgent
from src.agents.response import ResponseAgent

logger = logging.getLogger(__name__)

# Agent 元数据（名称、图标、顺序）
AGENT_PIPELINE = [
    {"name": "语义意图分析", "icon": "🧠"},
    {"name": "多维关联检测", "icon": "🔍"},
    {"name": "风险研判", "icon": "⚖️"},
    {"name": "响应处置", "icon": "🛡️"},
]


def run_analysis(email: EmailInput, callback: Callable[[dict], None] = None):
    """
    执行完整的邮件检测工作流

    Args:
        email: 待分析的邮件
        callback: 事件回调函数，每次 Agent 产生事件时调用

    Returns:
        完整的分析报告字典
    """
    def emit(event_type: str, data: dict):
        """推送事件到前端"""
        if callback:
            callback({"type": event_type, "data": data})

    # ---- 初始化 Agent 实例 ----
    semantic_agent = SemanticAgent()
    detector_agent = DetectorAgent()
    risk_agent = RiskAgent()
    response_agent = ResponseAgent()

    # ---- 存储各 Agent 结果 ----
    semantic_result = None
    detection_result = None
    risk_result = None
    response_result = None
    is_phishing = False

    try:
        # ============================================================
        # Agent #1: 语义意图分析
        # ============================================================
        emit("agent_start", {"agent": "语义意图分析", "icon": "🧠", "index": 0})

        result1 = semantic_agent.analyze(email, callback=callback)
        semantic_result = result1["semantic"]

        emit("agent_done", {
            "agent": "语义意图分析",
            "result": {
                "intent": semantic_result.intent,
                "confidence": semantic_result.confidence,
                "techniques": semantic_result.persuasion_techniques,
                "explanation": semantic_result.explanation[:200],
            }
        })

        # ============================================================
        # Agent #2: 多维关联检测
        # ============================================================
        emit("agent_start", {"agent": "多维关联检测", "icon": "🔍", "index": 1})

        result2 = detector_agent.analyze(
            email, callback=callback, semantic_result=semantic_result
        )
        detection_result = result2["detection"]

        emit("agent_done", {
            "agent": "多维关联检测",
            "result": {
                "sender_score": detection_result.sender_score,
                "url_score": detection_result.url_score,
                "content_flags": detection_result.content_flags,
                "explanation": detection_result.explanation[:200],
            }
        })

        # ============================================================
        # Agent #3: 风险研判
        # ============================================================
        emit("agent_start", {"agent": "风险研判", "icon": "⚖️", "index": 2})

        result3 = risk_agent.analyze(
            email, callback=callback,
            semantic_result=semantic_result,
            detection_result=detection_result,
        )
        risk_result = result3["risk"]
        is_phishing = result3["is_phishing"]

        emit("agent_done", {
            "agent": "风险研判",
            "result": {
                "risk_score": risk_result.risk_score,
                "risk_level": risk_result.risk_level,
                "attack_techniques": risk_result.attack_techniques,
                "explanation": risk_result.explanation[:200],
            }
        })

        # ============================================================
        # Agent #4: 响应处置
        # ============================================================
        emit("agent_start", {"agent": "响应处置", "icon": "🛡️", "index": 3})

        result4 = response_agent.analyze(
            email, callback=callback,
            semantic_result=semantic_result,
            detection_result=detection_result,
            risk_result=risk_result,
        )
        response_result = result4["response"]

        emit("agent_done", {
            "agent": "响应处置",
            "result": {
                "action": response_result.action,
                "alert_message": response_result.alert_message,
                "recommendation": response_result.recommendation,
            }
        })

    except Exception as e:
        logger.error(f"工作流执行失败: {e}", exc_info=True)
        emit("error", {"message": str(e)})
        return {"error": str(e)}

    # ============================================================
    # 汇总完整报告
    # ============================================================
    report = {
        "is_phishing": is_phishing,
        "risk_score": risk_result.risk_score if risk_result else 0,
        "risk_level": risk_result.risk_level if risk_result else "unknown",
        "semantic": {
            "intent": semantic_result.intent,
            "confidence": semantic_result.confidence,
            "persuasion_techniques": semantic_result.persuasion_techniques,
            "explanation": semantic_result.explanation,
        } if semantic_result else {},
        "detection": {
            "sender_score": detection_result.sender_score,
            "sender_analysis": detection_result.sender_analysis,
            "url_score": detection_result.url_score,
            "url_analysis": detection_result.url_analysis,
            "content_flags": detection_result.content_flags,
            "explanation": detection_result.explanation,
        } if detection_result else {},
        "risk": {
            "risk_score": risk_result.risk_score,
            "risk_level": risk_result.risk_level,
            "attack_techniques": risk_result.attack_techniques,
            "explanation": risk_result.explanation,
        } if risk_result else {},
        "response": {
            "action": response_result.action,
            "alert_message": response_result.alert_message,
            "trace_report": response_result.trace_report,
            "recommendation": response_result.recommendation,
        } if response_result else {},
    }

    emit("complete", report)
    return report
