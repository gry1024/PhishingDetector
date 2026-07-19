"""
语义意图分析 Agent（Agent #1）
==============================
核心职责：用 LLM 理解邮件的真实意图，而非关键词匹配。

工具集：
- scan_phishing_patterns: 正则扫描已知钓鱼话术模式
- extract_urls: 提取邮件中的 URL

工作流：
1. 先调用工具做规则预扫描（快速、低成本）
2. 将预扫描结果 + 邮件全文传给 LLM 做深度语义分析
3. 输出意图分类、话术类型、置信度
"""

from src.agents.base import BaseAgent, EventCallback
from src.models import EmailInput, SemanticResult
from src.tools import SEMANTIC_TOOLS


SYSTEM_PROMPT = """你是一个钓鱼邮件语义分析专家。你的核心能力是理解邮件的真实意图，而不是依赖关键词匹配。

分析维度：
1. 邮件意图分类：phishing（钓鱼）/ legitimate（正常）/ suspicious（可疑）
2. 社会工程话术识别：
   - urgency: 制造紧急感（"立即"、"24小时内"、"账户冻结"）
   - authority: 冒充权威（CEO、IT部门、银行）
   - fear: 恐惧诱导（"账户被盗"、"法律后果"）
   - greed: 利益诱惑（"中奖"、"退款"）
   - impersonation: 身份冒充
   - credential_theft: 凭证窃取（要求输入密码/验证码）
   - secrecy: 要求保密（BEC特征）
3. AI生成特征：语法完美但意图可疑、缺乏个性化细节

以严格JSON返回：
{
    "intent": "phishing/legitimate/suspicious",
    "persuasion_techniques": ["话术类型列表"],
    "explanation": "详细分析推理过程",
    "confidence": 0.0到1.0
}"""


class SemanticAgent(BaseAgent):
    """语义意图分析 Agent"""

    name = "语义意图分析"
    icon = "🧠"
    tools = SEMANTIC_TOOLS

    def analyze(self, email: EmailInput, callback: EventCallback = None, **kwargs) -> dict:
        """
        执行语义意图分析

        流程：工具预扫描 → LLM 深度分析 → 结果封装
        """
        # ---- Step 1: 工具预扫描 ----
        combined_text = f"{email.subject} {email.body}"

        self.call_tool("scan_phishing_patterns", combined_text, callback=callback)

        url_result = self.call_tool("extract_urls", combined_text, callback=callback)

        # ---- Step 2: 构造 LLM 提示 ----
        user_prompt = self._build_prompt(email)

        # ---- Step 3: LLM 语义分析 ----
        result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)

        semantic = SemanticResult(
            intent=result.get("intent", "suspicious"),
            persuasion_techniques=result.get("persuasion_techniques", []),
            explanation=result.get("explanation", ""),
            confidence=float(result.get("confidence", 0.5)),
        )

        return {"semantic": semantic}

    def _build_prompt(self, email: EmailInput) -> str:
        """构造 LLM 分析提示"""
        if email.raw_text:
            return f"请分析以下邮件的意图：\n\n{email.raw_text}"

        parts = []
        if email.subject:
            parts.append(f"主题: {email.subject}")
        if email.sender:
            parts.append(f"发件人: {email.sender}")
        if email.body:
            parts.append(f"正文:\n{email.body}")
        if email.urls:
            parts.append(f"URL: {', '.join(email.urls)}")
        if email.has_attachment:
            parts.append("⚠️ 包含附件")

        return f"请分析以下邮件的意图：\n\n" + "\n".join(parts)
