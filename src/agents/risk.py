"""
风险研判 Agent（Agent #3）
==========================
核心职责：综合所有分析结果，做出最终风险判定。

工具集：
- map_attack_techniques: 将检测标记映射到 MITRE ATT&CK 框架

工作流：
1. 收集 Agent#1 和 Agent#2 的结果
2. 规则引擎快速预评分
3. 调用 ATT&CK 映射工具
4. LLM 综合研判
5. 融合规则分和 LLM 分，输出最终风险等级
6. LLM 不可用时自动启用规则化风险研判兜底
"""

from src.agents.base import BaseAgent, EventCallback
from src.models import (
    EmailInput, SemanticResult, DetectionResult, RiskResult,
)
from src.tools import get_tools_for_agent


SYSTEM_PROMPT = """你是网络安全风险研判专家。综合语义分析和多维检测结果，做出最终风险判定。

评分标准（0-100，越高越危险）：
- 0-20: safe | 21-40: low | 41-60: medium | 61-80: high | 81-100: critical

MITRE ATT&CK 映射：
T1566: Phishing | T1566.001: 附件钓鱼 | T1566.002: 链接钓鱼
T1566.003: 服务钓鱼 | T1598: 信息钓鱼 | T1657: 金融盗窃

重点关注：
- AI 生成钓鱼（语法完美但意图可疑）
- BEC 商务邮件欺诈
- 凭证窃取

请先用自然语言详细研判风险等级、攻击手法和关键证据（200-400字），
然后在新的一行输出 <<<JSON>>> 标记，最后输出严格 JSON：
{
    "risk_score": 0到100的整数,
    "risk_level": "critical/high/medium/low/safe",
    "attack_techniques": ["ATT&CK编号列表"],
    "explanation": "详细研判推理过程"
}"""


class RiskAgent(BaseAgent):
    """风险研判 Agent"""

    name = "风险研判"
    icon = "⚖️"
    tools = get_tools_for_agent("risk")

    def analyze(
        self,
        email: EmailInput,
        callback: EventCallback = None,
        semantic_result: SemanticResult = None,
        detection_result: DetectionResult = None,
        **kwargs,
    ) -> dict:
        """
        执行风险研判

        流程：规则预评分 → ATT&CK映射 → LLM综合研判 → 分数融合
        LLM 不可用时自动降级为规则化研判兜底。
        """
        semantic = semantic_result or SemanticResult(
            intent="suspicious", explanation="", persuasion_techniques=[]
        )
        detection = detection_result or DetectionResult(
            sender_analysis="", url_analysis="", explanation=""
        )

        # ---- Step 1: 规则引擎预评分 ----
        self.emit_thinking("📏 规则引擎预评分中...\n", callback)
        rule_score = self._rule_risk_score(semantic, detection)
        self.emit_thinking(f"   规则预评分结果：{rule_score}/100\n", callback)

        # ---- Step 2: ATT&CK 映射 ----
        self.emit_thinking("🗺️ 映射 MITRE ATT&CK 攻击技术...\n", callback)
        all_flags = (
            semantic.persuasion_techniques +
            detection.content_flags
        )
        attack_result = self.call_tool("map_attack_techniques", all_flags, callback=callback)

        # ---- Step 3: LLM 综合研判（带规则兜底） ----
        self.emit_thinking(
            "⚖️ 综合前两步结果，正在由 LLM 进行最终风险研判...\n"
            "   研判维度：语义意图 × 检测特征 × ATT&CK 映射 × 规则评分\n",
            callback,
        )
        user_prompt = self._build_prompt(email, semantic, detection, rule_score)
        try:
            llm_result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)
        except Exception:
            self.emit_thinking("⚠️ LLM不可用，启用规则化风险研判...\n", callback)
            llm_result = self._fallback_llm_result(rule_score, semantic, detection)

        # ---- Step 4: 分数融合 ----
        llm_score = int(llm_result.get("risk_score", 50))
        final_score = round(llm_score * 0.6 + rule_score * 0.4)
        final_score = max(0, min(100, final_score))
        risk_level = self._score_to_level(final_score)

        # 合并 ATT&CK 技术（LLM + 工具）
        llm_techniques = llm_result.get("attack_techniques", [])
        tool_techniques = []
        if "T" in attack_result.output:
            import re
            tool_techniques = re.findall(r'T\d+(?:\.\d+)?', attack_result.output)
        all_techniques = list(set(llm_techniques + tool_techniques))

        risk = RiskResult(
            risk_score=final_score,
            risk_level=risk_level,
            attack_techniques=all_techniques,
            explanation=llm_result.get("explanation", ""),
        )

        return {
            "risk": risk,
            "is_phishing": final_score >= 60,
        }

    def _fallback_llm_result(self, rule_score: int, semantic: SemanticResult, detection: DetectionResult) -> dict:
        """LLM 不可用时的规则化最终判定。"""
        score = max(rule_score, 0)
        risk_level = self._score_to_level(score)
        return {
            "risk_score": score,
            "risk_level": risk_level,
            "attack_techniques": ["T1566", "T1598"],
            "explanation": "LLM不可用时采用规则引擎兜底进行风险研判，聚焦语义意图、URL可信度以及邮件头校验异常。",
        }

    def _rule_risk_score(self, semantic: SemanticResult, detection: DetectionResult) -> int:
        """规则引擎快速预评分"""
        score = 0
        if semantic.intent == "phishing":
            score += 40
        elif semantic.intent == "suspicious":
            score += 20
        score += min(len(semantic.persuasion_techniques) * 5, 20)
        score += int((1 - detection.sender_score) * 20)
        score += int((1 - detection.url_score) * 15)
        score += min(len(detection.content_flags) * 3, 15)
        return min(score, 100)

    def _score_to_level(self, score: int) -> str:
        """分数 → 风险等级"""
        if score >= 81: return "critical"
        if score >= 61: return "high"
        if score >= 41: return "medium"
        if score >= 21: return "low"
        return "safe"

    def _build_prompt(self, email, semantic, detection, rule_score) -> str:
        """构造研判提示"""
        parts = ["--- 邮件概要 ---"]
        if email.subject: parts.append(f"主题: {email.subject}")
        if email.sender: parts.append(f"发件人: {email.sender}")
        if email.body:
            body = email.body[:800] + ("..." if len(email.body) > 800 else "")
            parts.append(f"正文: {body}")

        parts.append(f"\n--- 语义分析 ---")
        parts.append(f"意图: {semantic.intent} | 置信度: {semantic.confidence:.0%}")
        parts.append(f"话术: {', '.join(semantic.persuasion_techniques) or '无'}")
        parts.append(f"分析: {semantic.explanation[:400]}")

        parts.append(f"\n--- 多维检测 ---")
        parts.append(f"发件人可信度: {detection.sender_score:.2f}")
        parts.append(f"URL安全: {detection.url_score:.2f}")
        if detection.content_flags:
            parts.append(f"内容标记: {', '.join(detection.content_flags)}")

        parts.append(f"\n规则预评分: {rule_score}/100")

        return "请综合以下分析结果，做出最终风险研判：\n\n" + "\n".join(parts)
