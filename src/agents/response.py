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

请先用自然语言详细说明处置决策依据、攻击溯源和安全建议（200-400字），
然后在新的一行输出 <<<JSON>>> 标记，最后输出严格 JSON：
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
            self.emit_thinking("邮件风险等级为 safe，触发快速放行通道，无需调用 LLM。", callback)
            self.emit_sub_step("根据风险等级直接匹配处置策略：safe → pass（正常放行）", "done", callback)
            return {"response": ResponseResult(
                action="pass",
                alert_message="",
                trace_report="",
                recommendation="此邮件安全，可正常处理。",
            )}

        # ---- 钓鱼邮件：生成处置报告 ----
        self.emit_thinking(
            f"风险等级为 {risk.risk_level}（{risk.risk_score}/100），需要生成处置方案。"
        )
        self.emit_sub_step(
            f"匹配策略映射：{risk.risk_level} → 强制处置动作 {self._enforce_policy('alert', risk.risk_level)}",
            "done",
            callback,
        )
        self.emit_sub_step(
            "调用 LLM 分析攻击手法、生成告警消息、溯源摘要和用户建议",
            "running",
            callback,
        )

        user_prompt = self._build_prompt(
            email,
            semantic_result or SemanticResult(intent="suspicious", explanation="", persuasion_techniques=[]),
            detection_result or DetectionResult(sender_analysis="", url_analysis="", explanation=""),
            risk,
        )
        try:
            llm_result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)
            self.emit_sub_step("LLM 生成处置报告完成，提取 action、alert_message、trace_report、recommendation", "done", callback)
        except Exception as e:
            self.emit_thinking("⚠️ LLM 不可用，已启用规则化响应兜底。", callback)
            self.emit_sub_step(f"规则兜底接管：按风险等级匹配默认处置策略（原因：{str(e)[:80]}）", "done", callback)
            llm_result = self._fallback_response_result(risk)

        # 强制执行策略映射（安全底线）
        action = llm_result.get("action", "alert")
        action = self._enforce_policy(action, risk.risk_level)
        self.emit_sub_step(f"最终处置动作：{action}（已强制执行策略安全底线）", "done", callback)

        response = ResponseResult(
            action=action,
            alert_message=llm_result.get("alert_message", ""),
            trace_report=llm_result.get("trace_report", ""),
            recommendation=llm_result.get("recommendation", ""),
        )

        self.emit_sub_step(
            f"响应处置完成：动作={action}，告警长度={len(response.alert_message)}字，建议长度={len(response.recommendation)}字",
            "done",
            callback,
        )

        return {"response": response}

    def _fallback_response_result(self, risk: RiskResult) -> dict:
        """LLM 不可用时的规则化响应兜底结果。"""
        policy = {"critical": "isolate", "high": "isolate", "medium": "quarantine", "low": "alert", "safe": "pass"}
        action = policy.get(risk.risk_level, "alert")
        return {
            "action": action,
            "alert_message": f"检测到风险等级为 {risk.risk_level}（{risk.risk_score}/100）的钓鱼邮件，已自动执行 {action} 处置。",
            "trace_report": (
                f"规则模式识别出高风险社工特征。攻击技术：{', '.join(risk.attack_techniques) or '未知'}。"
                f"风险研判说明：{risk.explanation[:120]}"
            ),
            "recommendation": "请勿点击邮件中的任何链接或下载附件，优先通过官方渠道人工确认，并同步安全团队进一步调查。",
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
