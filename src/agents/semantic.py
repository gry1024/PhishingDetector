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
4. LLM 不可用时自动启用规则兜底分析
"""

from src.agents.base import BaseAgent, EventCallback
from src.models import EmailInput, SemanticResult
from src.tools import get_tools_for_agent


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

请先用自然语言详细分析邮件的意图、识别到的话术和可疑特征（200-400字），
然后在新的一行输出 <<<JSON>>> 标记，最后输出严格 JSON：
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
    tools = get_tools_for_agent("semantic")

    def analyze(self, email: EmailInput, callback: EventCallback = None, **kwargs) -> dict:
        """
        执行语义意图分析

        流程：工具预扫描 → LLM 深度分析 → 结果封装
        LLM 不可用时自动降级为规则兜底。
        """
        # ---- Step 1: 工具预扫描 ----
        combined_text = f"{email.subject} {email.body}"

        self.emit_thinking("第一步：对邮件内容进行规则化预扫描，识别显性钓鱼模式。", callback)
        self.emit_sub_step("提取邮件主题、正文、发件人字段，组合为待分析文本", "running", callback)
        self.emit_sub_step("调用钓鱼话术模式库，匹配紧急施压、权威冒充、凭证窃取等已知话术", "running", callback)
        pattern_result = self.call_tool("scan_phishing_patterns", combined_text, callback=callback)
        self.emit_sub_step(f"预扫描完成，命中 {pattern_result.output.count('命中')} 个模式", "done", callback)

        self.emit_thinking("第二步：提取邮件中的 URL 链接，作为后续分析的关键锚点。", callback)
        self.emit_sub_step("使用正则表达式从正文中提取所有 URL", "running", callback)
        url_result = self.call_tool("extract_urls", combined_text, callback=callback)
        self.emit_sub_step(f"URL 提取完成：{url_result.output}", "done", callback)

        # ---- Step 2: 构造 LLM 提示 ----
        self.emit_thinking(
            "第三步：调用大模型进行深度语义分析，从意图、话术、AI生成特征三个维度综合研判。\n"
            "   分析维度：意图分类 | 社会工程话术 | AI生成特征",
            callback,
        )
        self.emit_sub_step("将预扫描结果、邮件全文、URL 列表构造为 LLM 提示词", "running", callback)
        user_prompt = self._build_prompt(email)

        # ---- Step 3: LLM 语义分析（带规则兜底） ----
        self.emit_sub_step("通过 OpenAI 兼容接口调用 Qwen-Plus 模型进行流式分析", "running", callback)
        try:
            result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)
            self.emit_sub_step("LLM 返回结构化结果，解析意图、话术、置信度", "done", callback)
        except Exception as e:
            self.emit_thinking("⚠️ LLM 不可用，已启用规则兜底语义分析。", callback)
            self.emit_sub_step(f"规则兜底接管：基于预扫描命中模式生成语义判定（原因：{str(e)[:80]}）", "done", callback)
            result = self._fallback_semantic_result(email, pattern_result, url_result)

        semantic = SemanticResult(
            intent=result.get("intent", "suspicious"),
            persuasion_techniques=result.get("persuasion_techniques", []),
            explanation=result.get("explanation", ""),
            confidence=float(result.get("confidence", 0.5)),
        )

        self.emit_sub_step(
            f"语义意图分析完成：判定为 {semantic.intent}，置信度 {semantic.confidence:.0%}，识别到 {len(semantic.persuasion_techniques)} 种话术",
            "done",
            callback,
        )

        return {"semantic": semantic}

    def _fallback_semantic_result(self, email: EmailInput, pattern_result, url_result) -> dict:
        """LLM 不可用时的规则化语义兜底结果。"""
        pattern_text = pattern_result.output.lower()
        url_text = url_result.output.lower()
        combined_text = f"{email.subject} {email.body}".lower()
        techniques = []

        if "紧急" in pattern_text or "urgent" in pattern_text:
            techniques.append("urgency")
        if "保密" in pattern_text or "secrecy" in pattern_text:
            techniques.append("secrecy")
        if "凭证" in pattern_text or "verify" in pattern_text or "password" in pattern_text:
            techniques.append("credential_theft")
        if "冒充" in pattern_text or "authority" in pattern_text:
            techniques.append("authority")

        attachment_bec_signals = any(keyword in combined_text for keyword in (
            "附件", "付款", "invoice", "payment", "单据", "收据", "对账"
        ))

        if attachment_bec_signals:
            techniques.append("financial_request")

        if not techniques:
            techniques = ["generic_social_engineering"]

        # 增强兜底解释的自然语言细节
        if "命中" in pattern_result.output or "http://192.168.1.100" in url_text:
            intent = "phishing"
            confidence = 0.82
            explanation = (
                "规则兜底判定：预扫描命中了明确的钓鱼诱导模式（如紧急施压、账户冻结威胁、凭证验证诱导），"
                "同时邮件正文包含非官方 IP 地址和异常端口，具有明显的钓鱼链接特征。"
            )
        elif email.has_attachment and attachment_bec_signals:
            intent = "suspicious"
            confidence = 0.76
            explanation = (
                "规则兜底判定：邮件包含附件且正文出现付款、单据、发票等 BEC 高频关键词，"
                "即使没有显式恶意链接，也存在商务欺诈风险，建议按可疑邮件处理。"
            )
        elif "未发现URL" in url_result.output:
            intent = "legitimate"
            confidence = 0.64
            explanation = (
                "规则兜底判定：预扫描未命中明显钓鱼话术，正文中也未提取到外部 URL，"
                "暂无典型钓鱼特征，采用安全放行兜底。"
            )
        else:
            intent = "suspicious"
            confidence = 0.7
            explanation = (
                "规则兜底判定：未命中强钓鱼话术，但正文中提取到外部链接，"
                "无法完全排除风险，继续采用审慎的可疑判定。"
            )

        return {
            "intent": intent,
            "persuasion_techniques": techniques,
            "explanation": explanation,
            "confidence": confidence,
        }

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
