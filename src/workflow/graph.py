"""
检测工作流
===========
串行执行 4 个 Agent，通过回调函数实时推送事件到前端。

流程：语义分析 → 多维检测 → 风险研判 → 响应处置

使用 WorkflowState 模型在各 Agent 间传递状态，保证类型安全。

每个 Agent 执行期间，通过 callback 推送：
- agent_start: Agent 开始
- thinking: 思考过程（含 LLM 流式输出）
- tool_call: 工具调用结果
- agent_done: Agent 完成，附带结果摘要
- complete: 全流程完成
- error: 执行出错
"""

import logging
from threading import Lock, Thread
from typing import Callable, Optional

from src.models import EmailInput, WorkflowState, EvidenceItem
from src.agents.semantic import SemanticAgent
from src.agents.detector import DetectorAgent
from src.agents.risk import RiskAgent
from src.agents.response import ResponseAgent

logger = logging.getLogger(__name__)

# Agent 元数据（名称、图标、顺序）
AGENT_PIPELINE = [
    {"id": "semantic", "name": "语义意图分析", "icon": "🧠", "index": 0},
    {"id": "detector", "name": "多维关联检测", "icon": "🔍", "index": 1},
    {"id": "risk", "name": "风险研判", "icon": "⚖️", "index": 2},
    {"id": "response", "name": "响应处置", "icon": "🛡️", "index": 3},
]

AGENT_PIPELINE_BY_ID = {item["id"]: item for item in AGENT_PIPELINE}
AGENT_LAYER_BY_ID = {
    "semantic": 1,
    "detector": 1,
    "risk": 2,
    "response": 2,
}


def run_analysis(
    email: EmailInput,
    callback: Callable[[dict], None] = None,
    selected_steps: Optional[list[str]] = None,
    execution_mode: str = "serial",
):
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

    def build_evidence_items(email: EmailInput, semantic, detection, risk) -> list[dict]:
        """基于各 Agent 输出构建规范化的结构化证据列表。"""
        evidence_items = []

        if semantic:
            evidence_items.append({
                "type": "semantic",
                "source": "semantic_agent",
                "weight": 25,
                "confidence": max(0.0, min(1.0, float(semantic.confidence))),
                "reason": semantic.explanation[:200] or semantic.intent,
            })

        if detection:
            evidence_items.append({
                "type": "detection",
                "source": "detector_agent",
                "weight": 30,
                "confidence": max(0.0, min(1.0, float((detection.sender_score + detection.url_score) / 2))),
                "reason": detection.explanation[:200] or ",".join(detection.content_flags),
            })

            if getattr(detection, "url_reputation_score", None) is not None and getattr(detection, "url_reputation_summary", None):
                reputation_confidence = max(0.0, min(1.0, float(detection.url_reputation_score)))
                evidence_items.append({
                    "type": "url_reputation",
                    "source": "detector_agent",
                    "weight": 15,
                    "confidence": reputation_confidence,
                    "reason": detection.url_reputation_summary[:200],
                })

            if getattr(detection, "attachment_score", 0) >= 0.4 and getattr(detection, "attachment_summary", None):
                evidence_items.append({
                    "type": "attachment",
                    "source": "detector_agent",
                    "weight": 12,
                    "confidence": max(0.0, min(1.0, float(detection.attachment_score))),
                    "reason": detection.attachment_summary[:200],
                })

            if getattr(detection, "behavior_score", 0) >= 0.4 and getattr(detection, "behavior_summary", None):
                evidence_items.append({
                    "type": "behavior_anomaly",
                    "source": "detector_agent",
                    "weight": 12,
                    "confidence": max(0.0, min(1.0, float(detection.behavior_score))),
                    "reason": detection.behavior_summary[:200],
                })

        header_risk = 0.0
        if isinstance(email.headers, dict):
            headers = email.headers or {}
            for status in (headers.get("spf", ""), headers.get("dkim", ""), headers.get("dmarc", "")):
                value = str(status).lower()
                if value in {"none", "neutral"}:
                    header_risk += 20
                elif value == "fail":
                    header_risk += 40
        header_risk = min(header_risk, 100)

        if header_risk >= 40:
            evidence_items.append({
                "type": "header_validation",
                "source": "mail_headers",
                "weight": 15,
                "confidence": 0.9,
                "reason": "SPF/DKIM/DMARC 头部校验存在异常，说明邮件身份真实性下降。",
            })

        if email.has_attachment:
            evidence_items.append({
                "type": "attachment",
                "source": "attachment_check",
                "weight": 10,
                "confidence": 0.75,
                "reason": "邮件包含附件，附件诱导钓鱼风险需要进一步审查。",
            })

        if risk:
            evidence_items.append({
                "type": "risk",
                "source": "risk_agent",
                "weight": 20,
                "confidence": max(0.0, min(1.0, float(risk.risk_score / 100))),
                "reason": risk.explanation[:200] or risk.risk_level,
            })

        total = sum(item["weight"] for item in evidence_items)
        if total <= 0:
            total = 1

        normalized = []
        for item in evidence_items:
            normalized.append({
                **item,
                "weight": int(round(item["weight"] / total * 100)),
            })

        # 由于四舍五入可能导致总和不等于 100，使用差额补齐最后一条
        diff = 100 - sum(item["weight"] for item in normalized)
        if normalized:
            normalized[-1]["weight"] += diff

        return normalized

    # ---- 初始化工作流状态 ----
    state = WorkflowState(email=email)

    # ---- 规范化执行步骤 ----
    # 响应处置依赖风险研判：如果选择了 response 但未选择 risk，自动补齐 risk。
    ordered_step_ids = [item["id"] for item in AGENT_PIPELINE]
    if selected_steps:
        selected = []
        for step in selected_steps:
            if step in AGENT_PIPELINE_BY_ID and step not in selected:
                selected.append(step)

        if "response" in selected and "risk" not in selected:
            response_idx = selected.index("response")
            selected.insert(response_idx, "risk")
            emit("thinking", {
                "agent": "系统",
                "chunk": "⚙️ 检测到已选择响应处置但缺少风险研判，已自动补齐 risk 步骤以保证处置一致性。",
            })

        # 分层执行：先分析层，再决策层；同层内保持工作流定义顺序。
        selected = sorted(
            selected,
            key=lambda step_id: (AGENT_LAYER_BY_ID.get(step_id, 99), AGENT_PIPELINE_BY_ID[step_id]["index"]),
        )

        steps_to_run = selected or ordered_step_ids
    else:
        steps_to_run = ordered_step_ids

    # ---- 初始化 Agent 实例 ----
    semantic_agent = SemanticAgent()
    detector_agent = DetectorAgent()
    risk_agent = RiskAgent()
    response_agent = ResponseAgent()

    def run_single_step(step_id: str):
        """运行单个步骤，包含开始/结束事件。"""
        nonlocal state

        meta = AGENT_PIPELINE_BY_ID[step_id]
        emit("agent_start", {
            "agent": meta["name"],
            "icon": meta["icon"],
            "index": meta["index"],
            "step_id": step_id,
        })

        if step_id == "semantic":
            result = semantic_agent.analyze(email, callback=callback)
            state.semantic = result["semantic"]
            emit("agent_done", {
                "agent": meta["name"],
                "step_id": step_id,
                "result": {
                    "intent": state.semantic.intent,
                    "confidence": state.semantic.confidence,
                    "techniques": state.semantic.persuasion_techniques,
                    "explanation": state.semantic.explanation[:200],
                },
            })
            return

        if step_id == "detector":
            result = detector_agent.analyze(
                email,
                callback=callback,
                semantic_result=state.semantic,
            )
            state.detection = result["detection"]
            emit("agent_done", {
                "agent": meta["name"],
                "step_id": step_id,
                "result": {
                    "sender_score": state.detection.sender_score,
                    "url_score": state.detection.url_score,
                    "content_flags": state.detection.content_flags,
                    "kb_hits": state.detection.kb_hits,
                    "explanation": state.detection.explanation[:200],
                },
            })
            return

        if step_id == "risk":
            result = risk_agent.analyze(
                email,
                callback=callback,
                semantic_result=state.semantic,
                detection_result=state.detection,
            )
            state.risk = result["risk"]
            state.is_phishing = result["is_phishing"]
            emit("agent_done", {
                "agent": meta["name"],
                "step_id": step_id,
                "result": {
                    "risk_score": state.risk.risk_score,
                    "risk_level": state.risk.risk_level,
                    "rule_score": state.risk.rule_score,
                    "llm_score": state.risk.llm_score,
                    "score_gap": state.risk.score_gap,
                    "consistency_warning": state.risk.consistency_warning,
                    "attack_techniques": state.risk.attack_techniques,
                    "explanation": state.risk.explanation[:200],
                },
            })
            return

        if step_id == "response":
            result = response_agent.analyze(
                email,
                callback=callback,
                semantic_result=state.semantic,
                detection_result=state.detection,
                risk_result=state.risk,
            )
            state.response = result["response"]
            emit("agent_done", {
                "agent": meta["name"],
                "step_id": step_id,
                "result": {
                    "action": state.response.action,
                    "alert_message": state.response.alert_message,
                    "recommendation": state.response.recommendation,
                },
            })
            return

    try:
        cluster_enabled = execution_mode == "cluster"
        can_parallel = cluster_enabled and "semantic" in steps_to_run and "detector" in steps_to_run

        if can_parallel:
            emit("thinking", {
                "agent": "系统",
                "chunk": "🚀 并行集群模式：语义意图分析 + 多维关联检测并行执行，后续步骤进行融合判定。",
            })

            errors = []
            err_lock = Lock()

            def _run_parallel(step_id: str):
                try:
                    run_single_step(step_id)
                except Exception as e:
                    with err_lock:
                        errors.append(e)

            t_semantic = Thread(target=_run_parallel, args=("semantic",), daemon=True)
            t_detector = Thread(target=_run_parallel, args=("detector",), daemon=True)
            t_semantic.start()
            t_detector.start()
            t_semantic.join()
            t_detector.join()

            if errors:
                raise errors[0]

            remaining = [s for s in steps_to_run if s not in {"semantic", "detector"}]
            for step_id in remaining:
                run_single_step(step_id)
        else:
            for step_id in steps_to_run:
                run_single_step(step_id)

    except Exception as e:
        logger.error(f"工作流执行失败: {e}", exc_info=True)
        emit("error", {"message": str(e)})
        return {"error": str(e)}

    # ============================================================
    # 汇总完整报告（从 WorkflowState 提取）
    # ============================================================
    state.evidence_items = [
        EvidenceItem(**item)
        for item in build_evidence_items(
            email=email,
            semantic=state.semantic,
            detection=state.detection,
            risk=state.risk,
        )
    ]

    report = {
        "is_phishing": state.is_phishing,
        "risk_score": state.risk.risk_score if state.risk else 0,
        "risk_level": state.risk.risk_level if state.risk else "unknown",
        "semantic": {
            "intent": state.semantic.intent,
            "confidence": state.semantic.confidence,
            "persuasion_techniques": state.semantic.persuasion_techniques,
            "explanation": state.semantic.explanation,
        } if state.semantic else {},
        "detection": {
            "sender_score": state.detection.sender_score,
            "sender_analysis": state.detection.sender_analysis,
            "url_score": state.detection.url_score,
            "url_analysis": state.detection.url_analysis,
            "url_reputation_score": state.detection.url_reputation_score,
            "url_reputation_summary": state.detection.url_reputation_summary,
            "attachment_score": state.detection.attachment_score,
            "attachment_summary": state.detection.attachment_summary,
            "behavior_score": state.detection.behavior_score,
            "behavior_summary": state.detection.behavior_summary,
            "content_flags": state.detection.content_flags,
            "kb_hits": state.detection.kb_hits,
            "kb_summary": state.detection.kb_summary,
            "explanation": state.detection.explanation,
        } if state.detection else {},
        "risk": {
            "risk_score": state.risk.risk_score,
            "risk_level": state.risk.risk_level,
            "rule_score": state.risk.rule_score,
            "llm_score": state.risk.llm_score,
            "score_gap": state.risk.score_gap,
            "consistency_warning": state.risk.consistency_warning,
            "attack_techniques": state.risk.attack_techniques,
            "explanation": state.risk.explanation,
        } if state.risk else {},
        "response": {
            "action": state.response.action,
            "alert_message": state.response.alert_message,
            "trace_report": state.response.trace_report,
            "recommendation": state.response.recommendation,
        } if state.response else {},
        "evidence_items": [
            item.model_dump(mode="json") for item in state.evidence_items
        ],
    }

    emit("complete", report)
    return report
