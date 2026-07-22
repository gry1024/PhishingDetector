"""
自主响应 Agent（Agent #4）
==========================
核心职责：根据风险等级决定处置动作，生成告警和溯源报告。

处置策略：
- critical/high → isolate（隔离）
- medium → quarantine（隔离待审）
- low → alert（告警放行）
- safe → pass（正常放行）

安全邮件快速放行，不调用 LLM。
钓鱼邮件调用 LLM 生成完整的告警消息、溯源分析和建议。
"""

from src.agents.base import BaseAgent, EventCallback
from src.models import (
    EmailInput, SemanticResult, DetectionResult,
    RiskResult, ResponseResult,
)


SYSTEM_PROMPT = """你是安全运营响应专家。根据风险评估结果生成处置报告。

处置动作：
- isolate: 立即隔离（critical/high）
- quarantine: 隔离待审（medium）
- alert: 标记告警（low）
- pass: 正常放行（safe）

以严格JSON返回：
{
    "action": "isolate/quarantine/alert/pass",
    "alert_message": "告警消息（简明扼要说明威胁）",
    "trace_report": "溯源分析摘要（攻击手法推测、可能目标）",
    "recommendation": "给用户的具体安全建议"
}"""


class ResponseAgent(BaseAgent):
    """自主响应 Agent"""

    name = "响应处置"
    icon = "🛡️"
    tools = {}

    def analyze(
        self,
        email: EmailInput,
        callback: EventCallback = None,
        semantic_result: SemanticResult = None,
        detection_result: DetectionResult = None,
        risk_result: RiskResult = None,
        **kwargs,
    ) -> dict:
        """
        执行响应处置

        流程：安全邮件快速放行 → 钓鱼邮件调用LLM生成报告
        """
        risk = risk_result or RiskResult(
            risk_score=0, risk_level="safe", attack_techniques=[], explanation=""
        )

        # ---- 安全邮件快速放行 ----
        if risk.risk_level == "safe":
            self.emit_thinking("邮件判定为安全，直接放行。", callback)
            return {"response": ResponseResult(
                action="pass",
                alert_message="",
                trace_report="",
                recommendation="此邮件安全，可正常处理。",
            )}

        # ---- 钓鱼邮件：生成处置报告 ----
        self.emit_thinking(f"风险等级 {risk.risk_level}，生成处置报告...", callback)

        user_prompt = self._build_prompt(
            email,
            semantic_result or SemanticResult(intent="suspicious", explanation="", persuasion_techniques=[]),
            detection_result or DetectionResult(sender_analysis="", url_analysis="", explanation=""),
            risk,
        )
        try:
            llm_result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)
        except Exception:
            self.emit_thinking("LLM不可用，启用规则化响应兜底...", callback)
            llm_result = self._fallback_response_result(risk)

        # 强制执行策略映射（安全底线）
        action = llm_result.get("action", "alert")
        action = self._enforce_policy(action, risk.risk_level)

        response = ResponseResult(
            action=action,
            alert_message=llm_result.get("alert_message", ""),
            trace_report=llm_result.get("trace_report", ""),
            recommendation=llm_result.get("recommendation", ""),
        )

        self.emit_thinking(f"处置动作: {response.action}", callback)

        return {"response": response}

    def _fallback_response_result(self, risk: RiskResult) -> dict:
        """LLM 不可用时的规则化响应兜底结果。"""
        policy = {"critical": "isolate", "high": "isolate", "medium": "quarantine", "low": "alert", "safe": "pass"}
        action = policy.get(risk.risk_level, "alert")
        return {
            "action": action,
            "alert_message": f"风险等级为 {risk.risk_level}，已按规则策略执行自动处置。",
            "trace_report": "规则模式识别出高风险社工特征，建议即时隔离并进行人工复核。",
            "recommendation": "请勿点击邮件中的任何链接，优先人工确认并同步安全团队。",
        }

    def _enforce_policy(self, action: str, risk_level: str) -> str:
        """强制执行处置策略（防止 LLM 错误放行高风险邮件）"""
        policy = {"critical": "isolate", "high": "isolate", "medium": "quarantine", "low": "alert", "safe": "pass"}
        severity = {"pass": 0, "alert": 1, "quarantine": 2, "isolate": 3}
        policy_action = policy.get(risk_level, "alert")
        if severity.get(action, 0) >= severity.get(policy_action, 0):
            return action
        return policy_action

    def _build_prompt(self, email, semantic, detection, risk) -> str:
        """构造响应提示"""
        parts = [f"风险评分: {risk.risk_score}/100 | 等级: {risk.risk_level}"]
        if risk.attack_techniques:
            parts.append(f"ATT&CK: {', '.join(risk.attack_techniques)}")
        parts.append(f"研判: {risk.explanation[:400]}")

        if email.subject: parts.append(f"\n邮件主题: {email.subject}")
        if email.sender: parts.append(f"发件人: {email.sender}")
        if email.body: parts.append(f"正文摘要: {email.body[:300]}")

        parts.append(f"\n意图: {semantic.intent} | 话术: {', '.join(semantic.persuasion_techniques)}")
        parts.append(f"发件人可信度: {detection.sender_score:.2f} | URL安全: {detection.url_score:.2f}")

        return "请根据风险评估结果，生成处置报告：\n\n" + "\n".join(parts)
