"""
语义意图分析 Agent（Agent #1）
==============================
核心 Agent：使用 LLM 理解邮件的真实意图，而非依赖关键词匹配。
识别钓鱼邮件常用的社会工程话术：紧急感、权威施压、恐惧诱导等。

这是整个检测管线的第一步，也是最关键的一步——
即使邮件语法完美、无可疑链接，只要意图是欺诈就能识别。
"""

from src.agents.base import BaseAgent
from src.models import EmailInput, SemanticResult


# Agent #1 系统提示词：定义语义分析的角色和输出格式
SYSTEM_PROMPT = """你是一个专业的钓鱼邮件语义分析专家。你的任务是分析邮件的真实意图，而非仅仅检查关键词或格式。

你需要判断：
1. 这封邮件的真实意图是什么？（phishing=钓鱼 / legitimate=正常 / suspicious=可疑）
2. 邮件中使用了哪些社会工程话术？
3. 你的分析推理过程是什么？

常见的社会工程话术类型：
- urgency: 制造紧急感（"立即行动"、"24小时内"、"账户将被冻结"）
- authority: 冒充权威（"CEO"、"IT部门"、"银行"、"税务局"）
- fear: 引发恐惧（"账户被盗"、"法律后果"、"数据泄露"）
- greed: 利益诱惑（"中奖"、"退款"、"高额回报"）
- curiosity: 引发好奇（"查看您的文件"、"重要更新"）
- impersonation: 身份冒充（冒充同事、领导、服务商）
- credential_theft: 凭证窃取（要求输入密码、验证码）

请以严格的 JSON 格式返回分析结果：
{
    "intent": "phishing 或 legitimate 或 suspicious",
    "persuasion_techniques": ["检测到的话术类型列表"],
    "explanation": "详细的分析推理过程",
    "confidence": 0.0到1.0之间的置信度
}"""


class SemanticAgent(BaseAgent):
    """
    语义意图分析 Agent
    
    工作流程：
    1. 将邮件内容发送给 LLM，附带专业分析提示词
    2. LLM 返回结构化的意图分析结果
    3. 解析 JSON 响应并封装为 SemanticResult 模型
    
    这个 Agent 的关键价值：
    - 不依赖关键词黑名单，能识别 AI 生成的高质量钓鱼邮件
    - 识别社会工程话术，理解"邮件想让人做什么"
    - 提供可解释的分析推理过程
    """

    name = "语义意图分析"

    def analyze(self, email: EmailInput) -> dict:
        """
        执行语义意图分析
        
        Args:
            email: 待分析邮件
        
        Returns:
            包含 semantic 结果和 workflow_log 的字典
        """
        log = []
        log.append(self.log_step("开始语义意图分析..."))

        # 构造用户提示：将邮件各字段组合为自然语言描述
        user_prompt = self._build_prompt(email)
        log.append(self.log_step(f"邮件长度: {len(user_prompt)} 字符"))

        # 调用 LLM 进行语义分析
        log.append(self.log_step("正在调用 LLM 分析邮件意图..."))
        result = self.llm.chat_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        # 解析 LLM 返回的 JSON 结果
        semantic = SemanticResult(
            intent=result.get("intent", "suspicious"),
            persuasion_techniques=result.get("persuasion_techniques", []),
            explanation=result.get("explanation", "LLM 未返回分析说明"),
            confidence=float(result.get("confidence", 0.5)),
        )

        log.append(self.log_step(
            f"分析完成 → 意图: {semantic.intent} | "
            f"置信度: {semantic.confidence:.0%} | "
            f"话术: {', '.join(semantic.persuasion_techniques) or '无'}"
        ))

        return {
            "semantic": semantic,
            "workflow_log": log,
        }

    def _build_prompt(self, email: EmailInput) -> str:
        """
        将邮件数据构造为 LLM 可理解的自然语言提示
        
        如果 raw_text 存在，直接使用原始文本（适合用户直接粘贴场景）；
        否则拼接各字段。
        """
        if email.raw_text:
            return f"请分析以下邮件的意图：\n\n{email.raw_text}"

        parts = []
        if email.subject:
            parts.append(f"主题: {email.subject}")
        if email.sender:
            parts.append(f"发件人: {email.sender}")
        if email.recipients:
            parts.append(f"收件人: {email.recipients}")
        if email.body:
            parts.append(f"正文:\n{email.body}")
        if email.urls:
            parts.append(f"包含的URL: {', '.join(email.urls)}")
        if email.has_attachment:
            parts.append("注意: 此邮件包含附件")

        return f"请分析以下邮件的意图：\n\n" + "\n".join(parts)
