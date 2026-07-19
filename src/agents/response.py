"""
自主响应 Agent（Agent #4）
==========================
根据风险研判结果，自主决定处置动作：
- isolate: 隔离邮件（高风险/极高风险）
- quarantine: 隔离待审（中风险）
- alert: 发出告警（低风险）
- pass: 放行（安全）

同时生成告警消息和溯源分析报告。
这是工作流的最终环节，实现"检测→处置"的全自动闭环。
"""

from src.agents.base import BaseAgent
from src.models import (
    EmailInput, SemanticResult, DetectionResult,
    RiskResult, ResponseResult,
)


# Agent #4 系统提示词
SYSTEM_PROMPT = """你是一个安全运营响应专家。根据风险评估结果，你需要：

1. 决定处置动作：
   - isolate: 立即隔离（适用于 critical/high 风险）
   - quarantine: 隔离待人工审核（适用于 medium 风险）
   - alert: 标记告警但放行（适用于 low 风险）
   - pass: 正常放行（适用于 safe）

2. 生成告警消息（如果是钓鱼邮件）：
   - 简明扼要说明威胁类型和风险点
   - 提供具体的安全建议

3. 提供攻击溯源分析摘要：
   - 攻击手法推测
   - 可能的攻击目标

请以严格的 JSON 格式返回：
{
    "action": "isolate/quarantine/alert/pass",
    "alert_message": "告警消息（如果是钓鱼邮件）",
    "trace_report": "溯源分析摘要",
    "recommendation": "给用户的具体安全建议"
}"""


class ResponseAgent(BaseAgent):
    """
    自主响应 Agent
    
    工作流程：
    1. 根据风险等级快速确定处置动作
    2. 如果是钓鱼邮件，调用 LLM 生成告警和溯源报告
    3. 如果是安全邮件，直接放行
    
    设计原则：
    - 安全邮件快速放行，不影响用户体验
    - 钓鱼邮件自动生成完整处置报告
    - 所有处置动作可追溯、可审计
    """

    name = "自主响应"

    def analyze(
        self,
        email: EmailInput,
        semantic_result: SemanticResult,
        detection_result: DetectionResult,
        risk_result: RiskResult,
    ) -> dict:
        """
        执行响应处置
        
        Args:
            email: 原始邮件
            semantic_result: 语义分析结果
            detection_result: 多维检测结果
            risk_result: 风险研判结果
        
        Returns:
            包含 response 结果和 workflow_log 的字典
        """
        log = []
        log.append(self.log_step("开始响应处置..."))

        # ---- 安全邮件快速放行 ----
        if risk_result.risk_level == "safe":
            response = ResponseResult(
                action="pass",
                alert_message="",
                trace_report="",
                recommendation="此邮件安全，可正常处理。",
            )
            log.append(self.log_step("邮件判定为安全，已放行"))
            return {
                "response": response,
                "workflow_log": log,
            }

        # ---- 钓鱼邮件：调用 LLM 生成处置报告 ----
        log.append(self.log_step(
            f"风险等级: {risk_result.risk_level}，生成处置报告..."
        ))

        user_prompt = self._build_prompt(
            email, semantic_result, detection_result, risk_result
        )
        llm_result = self.llm.chat_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        # 确保 action 与风险等级一致
        action = llm_result.get("action", "alert")
        action = self._enforce_action_policy(action, risk_result.risk_level)

        response = ResponseResult(
            action=action,
            alert_message=llm_result.get("alert_message", ""),
            trace_report=llm_result.get("trace_report", ""),
            recommendation=llm_result.get("recommendation", ""),
        )

        log.append(self.log_step(f"处置完成 → 动作: {response.action}"))
        if response.alert_message:
            log.append(self.log_step(f"告警: {response.alert_message}"))

        return {
            "response": response,
            "workflow_log": log,
        }

    def _enforce_action_policy(self, action: str, risk_level: str) -> str:
        """
        强制执行处置策略映射
        
        即使 LLM 返回了不匹配的 action，也会被纠正为正确的策略。
        这是安全底线——不能让 LLM 错误地放行高风险邮件。
        """
        policy = {
            "critical": "isolate",
            "high": "isolate",
            "medium": "quarantine",
            "low": "alert",
            "safe": "pass",
        }
        # 如果 LLM 的 action 比策略更严格，保留 LLM 的（比如 medium 但 LLM 建议 isolate）
        severity = {"pass": 0, "alert": 1, "quarantine": 2, "isolate": 3}
        policy_action = policy.get(risk_level, "alert")
        if severity.get(action, 0) >= severity.get(policy_action, 0):
            return action  # LLM 建议的更严格，保留
        return policy_action  # 否则强制执行策略

    def _build_prompt(
        self,
        email: EmailInput,
        semantic: SemanticResult,
        detection: DetectionResult,
        risk: RiskResult,
    ) -> str:
        """构造响应处置提示"""
        parts = [f"--- 风险评估结果 ---"]
        parts.append(f"风险评分: {risk.risk_score}/100")
        parts.append(f"风险等级: {risk.risk_level}")
        if risk.attack_techniques:
            parts.append(f"ATT&CK 映射: {', '.join(risk.attack_techniques)}")
        parts.append(f"研判说明: {risk.explanation[:500]}")

        parts.append(f"\n--- 邮件信息 ---")
        if email.subject:
            parts.append(f"主题: {email.subject}")
        if email.sender:
            parts.append(f"发件人: {email.sender}")
        if email.body:
            parts.append(f"正文摘要: {email.body[:500]}")

        parts.append(f"\n--- 检测摘要 ---")
        parts.append(f"意图: {semantic.intent} ({', '.join(semantic.persuasion_techniques)})")
        parts.append(f"发件人可信度: {detection.sender_score:.2f}")
        parts.append(f"URL安全评分: {detection.url_score:.2f}")
        if detection.content_flags:
            parts.append(f"内容标记: {', '.join(detection.content_flags)}")

        return "请根据以下风险评估结果，生成处置报告：\n\n" + "\n".join(parts)
