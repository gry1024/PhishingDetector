"""
风险研判 Agent（Agent #3）
==========================
综合前两个 Agent 的分析结果，进行最终风险评估：
- 多维评分聚合
- MITRE ATT&CK 技战术映射
- 风险等级判定（critical/high/medium/low/safe）

这是"法官"角色——在听取所有证据后做出最终判决。
"""

from src.agents.base import BaseAgent
from src.models import (
    EmailInput, SemanticResult, DetectionResult, RiskResult,
)


# Agent #3 系统提示词
SYSTEM_PROMPT = """你是一个网络安全风险研判专家。你需要综合语义分析和多维检测的结果，做出最终的风险判定。

你的分析框架：
1. 综合评分：0-100 分，越高越危险
   - 0-20: safe（安全）
   - 21-40: low（低风险）
   - 41-60: medium（中风险）
   - 61-80: high（高风险）
   - 81-100: critical（极高风险/确认钓鱼）

2. MITRE ATT&CK 技战术映射（如果适用）：
   - T1566: Phishing（钓鱼攻击）
   - T1566.001: Spearphishing Attachment（鱼叉式钓鱼附件）
   - T1566.002: Spearphishing Link（鱼叉式钓鱼链接）
   - T1566.003: Spearphishing via Service（通过服务的鱼叉式钓鱼）
   - T1598: Phishing for Information（信息钓鱼）
   - T1657: Financial Theft（金融盗窃）

3. 你需要特别关注：
   - AI 生成钓鱼邮件的特征（语法完美但意图可疑）
   - BEC（商务邮件欺诈）模式
   - 凭证窃取尝试

请以严格的 JSON 格式返回：
{
    "risk_score": 0到100之间的整数,
    "risk_level": "critical/high/medium/low/safe",
    "attack_techniques": ["MITRE ATT&CK 技术编号列表"],
    "explanation": "详细的研判推理过程"
}"""


class RiskAgent(BaseAgent):
    """
    风险研判 Agent
    
    工作流程：
    1. 收集 Agent#1（语义分析）和 Agent#2（多维检测）的结果
    2. 构造综合评估提示，让 LLM 做出最终判定
    3. 同时使用规则引擎进行快速预评分，与 LLM 评分交叉验证
    
    设计原则：
    - LLM 负责复杂的综合推理
    - 规则引擎负责快速 baseline 评分
    - 两者交叉验证提高可靠性
    """

    name = "风险研判"

    def analyze(
        self,
        email: EmailInput,
        semantic_result: SemanticResult,
        detection_result: DetectionResult,
    ) -> dict:
        """
        执行风险研判
        
        Args:
            email: 原始邮件数据
            semantic_result: Agent#1 的语义分析结果
            detection_result: Agent#2 的多维检测结果
        
        Returns:
            包含 risk 结果和 workflow_log 的字典
        """
        log = []
        log.append(self.log_step("开始风险研判..."))

        # ---- 规则引擎预评分 ----
        rule_score = self._rule_risk_score(semantic_result, detection_result)
        log.append(self.log_step(f"规则预评分: {rule_score}/100"))

        # ---- LLM 综合研判 ----
        log.append(self.log_step("正在调用 LLM 进行综合风险研判..."))
        user_prompt = self._build_prompt(
            email, semantic_result, detection_result, rule_score
        )
        llm_result = self.llm.chat_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        # ---- 融合规则评分和 LLM 评分 ----
        llm_score = int(llm_result.get("risk_score", 50))
        # 加权融合：LLM 60%，规则 40%
        final_score = round(llm_score * 0.6 + rule_score * 0.4)
        final_score = max(0, min(100, final_score))

        # 根据最终分数确定风险等级
        risk_level = self._score_to_level(final_score)

        risk = RiskResult(
            risk_score=final_score,
            risk_level=risk_level,
            attack_techniques=llm_result.get("attack_techniques", []),
            explanation=llm_result.get("explanation", ""),
        )

        log.append(self.log_step(
            f"研判完成 → 风险评分: {risk.risk_score}/100 | "
            f"等级: {risk.risk_level} | "
            f"ATT&CK: {', '.join(risk.attack_techniques) or '无'}"
        ))

        return {
            "risk": risk,
            "is_phishing": final_score >= 60,
            "workflow_log": log,
        }

    def _rule_risk_score(
        self,
        semantic: SemanticResult,
        detection: DetectionResult,
    ) -> int:
        """
        基于规则引擎的快速风险预评分
        
        不依赖 LLM，纯规则计算。作为 LLM 研判的 baseline 参考。
        """
        score = 0

        # 语义意图评分
        if semantic.intent == "phishing":
            score += 40
        elif semantic.intent == "suspicious":
            score += 20

        # 社会工程话术数量
        score += min(len(semantic.persuasion_techniques) * 5, 20)

        # 发件人可信度（反转：越低越危险）
        score += int((1 - detection.sender_score) * 20)

        # URL安全性（反转：越低越危险）
        score += int((1 - detection.url_score) * 15)

        # 内容标记数量
        score += min(len(detection.content_flags) * 3, 15)

        return min(score, 100)

    def _score_to_level(self, score: int) -> str:
        """将风险分数映射为风险等级"""
        if score >= 81:
            return "critical"
        elif score >= 61:
            return "high"
        elif score >= 41:
            return "medium"
        elif score >= 21:
            return "low"
        return "safe"

    def _build_prompt(
        self,
        email: EmailInput,
        semantic: SemanticResult,
        detection: DetectionResult,
        rule_score: int,
    ) -> str:
        """构造综合研判提示"""
        parts = [f"--- 邮件概要 ---"]
        if email.subject:
            parts.append(f"主题: {email.subject}")
        if email.sender:
            parts.append(f"发件人: {email.sender}")
        if email.body:
            # 截断过长正文
            body_preview = email.body[:1000]
            if len(email.body) > 1000:
                body_preview += "...(已截断)"
            parts.append(f"正文摘要:\n{body_preview}")

        parts.append(f"\n--- 语义分析结果 ---")
        parts.append(f"判定意图: {semantic.intent}")
        parts.append(f"置信度: {semantic.confidence:.0%}")
        parts.append(f"话术类型: {', '.join(semantic.persuasion_techniques) or '无'}")
        parts.append(f"分析: {semantic.explanation[:500]}")

        parts.append(f"\n--- 多维检测结果 ---")
        parts.append(f"发件人可信度: {detection.sender_score:.2f}")
        parts.append(f"发件人分析: {detection.sender_analysis[:300]}")
        parts.append(f"URL安全评分: {detection.url_score:.2f}")
        parts.append(f"URL分析: {detection.url_analysis[:300]}")
        if detection.content_flags:
            parts.append(f"内容标记: {', '.join(detection.content_flags)}")

        parts.append(f"\n--- 规则引擎预评分 ---")
        parts.append(f"规则评分: {rule_score}/100")

        return "请综合以下分析结果，做出最终风险研判：\n\n" + "\n".join(parts)
