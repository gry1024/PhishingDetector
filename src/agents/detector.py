"""
多维关联检测 Agent（Agent #2）
==============================
从多个维度检测邮件的技术特征：
- 发件人可信度分析
- URL/链接安全性分析
- 内容特征标记检测

这个 Agent 结合了规则检测和 LLM 分析，弥补纯语义分析的盲区。
"""

import re
import logging
from urllib.parse import urlparse

from src.agents.base import BaseAgent
from src.models import EmailInput, DetectionResult, SemanticResult


# Agent #2 系统提示词
SYSTEM_PROMPT = """你是一个邮件安全技术检测专家。你需要从技术维度分析邮件的安全性。

请分析以下维度：
1. 发件人可信度：域名是否可疑、是否冒充知名机构、是否存在拼写变体（如 g00gle.com）
2. URL安全性：域名是否新注册、是否使用短链、URL中是否包含IP地址、是否有可疑路径
3. 内容标记：是否要求输入凭证、是否包含品牌冒充、是否有异常的格式化要求

请以严格的 JSON 格式返回：
{
    "sender_score": 0.0到1.0之间的发件人可信度（1.0=完全可信），
    "sender_analysis": "发件人分析说明",
    "url_score": 0.0到1.0之间的URL安全评分（1.0=完全安全），
    "url_analysis": "URL分析说明",
    "content_flags": ["检测到的内容标记列表"],
    "explanation": "综合技术分析说明"
}"""

# 已知的高可信域名后缀（用于规则检测辅助 LLM 判断）
TRUSTED_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "qq.com", "163.com", "126.com", "foxmail.com",
    "microsoft.com", "google.com", "apple.com",
}

# 常见钓鱼关键词模式（作为 LLM 分析的补充）
PHISHING_PATTERNS = [
    r"(verify|confirm|update|secure)\s+(your|my)\s+(account|password|card)",
    r"(click|visit|open)\s+(here|this|the link)",
    r"(suspended|locked|restricted|compromised)\s*(account|card)",
    r"(urgent|immediate|action required|respond within)",
    r"(wire transfer|bank detail|tax refund|lottery|prize)",
    r"(验证|确认|更新|冻结|锁定)\s*(账户|密码|银行)",
    r"(紧急|立即|马上|限时)\s*(操作|处理|回复|转账)",
    r"(中奖|退款|汇款|转账|打款)",
]


class DetectorAgent(BaseAgent):
    """
    多维关联检测 Agent
    
    工作流程：
    1. 规则引擎快速扫描（URL格式、发件人域名、关键词匹配）
    2. LLM 深度技术分析（结合规则扫描结果 + 邮件全文）
    3. 融合规则分数和 LLM 分析结果
    
    设计原则：
    - 规则引擎处理明确的特征（快速、低成本）
    - LLM 处理模糊的判断（慢速、高准确度）
    - 两者融合，互为补充
    """

    name = "多维关联检测"

    def analyze(
        self,
        email: EmailInput,
        semantic_result: SemanticResult | None = None,
    ) -> dict:
        """
        执行多维检测分析
        
        Args:
            email: 待分析邮件
            semantic_result: Agent#1 的语义分析结果（用于交叉验证）
        
        Returns:
            包含 detection 结果和 workflow_log 的字典
        """
        log = []
        log.append(self.log_step("开始多维关联检测..."))

        # ---- 第一层：规则引擎快速扫描 ----
        rule_results = self._rule_scan(email)
        log.append(self.log_step(
            f"规则扫描完成 → 发件人规则分: {rule_results['sender_score']:.2f} | "
            f"URL规则分: {rule_results['url_score']:.2f} | "
            f"标记数: {len(rule_results['content_flags'])}"
        ))

        # ---- 第二层：LLM 深度分析 ----
        log.append(self.log_step("正在调用 LLM 进行深度技术分析..."))
        user_prompt = self._build_prompt(email, rule_results, semantic_result)
        llm_result = self.llm.chat_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        # ---- 第三层：融合规则分数和 LLM 分析 ----
        detection = DetectionResult(
            # 规则分数和 LLM 分数加权融合（LLM 权重更高）
            sender_score=self._fuse_score(
                rule_results["sender_score"],
                float(llm_result.get("sender_score", 0.5)),
                llm_weight=0.7,
            ),
            sender_analysis=llm_result.get("sender_analysis", ""),
            url_score=self._fuse_score(
                rule_results["url_score"],
                float(llm_result.get("url_score", 0.5)),
                llm_weight=0.7,
            ),
            url_analysis=llm_result.get("url_analysis", ""),
            # 合并规则和 LLM 的内容标记
            content_flags=list(set(
                rule_results["content_flags"] +
                llm_result.get("content_flags", [])
            )),
            explanation=llm_result.get("explanation", ""),
        )

        log.append(self.log_step(
            f"检测完成 → 发件人分: {detection.sender_score:.2f} | "
            f"URL分: {detection.url_score:.2f} | "
            f"标记: {', '.join(detection.content_flags) or '无'}"
        ))

        return {
            "detection": detection,
            "workflow_log": log,
        }

    def _rule_scan(self, email: EmailInput) -> dict:
        """
        规则引擎快速扫描
        
        不依赖 LLM，纯规则匹配。用于提供 baseline 分数。
        """
        sender_score = 1.0
        url_score = 1.0
        content_flags = []

        # --- 发件人规则 ---
        if email.sender:
            domain = email.sender.split("@")[-1].lower() if "@" in email.sender else ""
            # 检查是否冒充可信域名（如 g00gle.com, micr0soft.com）
            for trusted in TRUSTED_DOMAINS:
                if trusted not in domain and self._is_typo(domain, trusted):
                    sender_score -= 0.5
                    content_flags.append("domain_typo_squatting")
                    break
            # 免费邮箱发送商务邮件
            free_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "qq.com", "163.com"}
            if domain in free_domains and any(
                kw in email.subject.lower()
                for kw in ["invoice", "payment", "银行", "转账", "发票"]
            ):
                sender_score -= 0.3
                content_flags.append("free_email_business_claim")

        # --- URL 规则 ---
        all_urls = email.urls + self._extract_urls(email.body)
        for url in all_urls:
            parsed = urlparse(url)
            # IP 地址作为域名
            if re.match(r"\d+\.\d+\.\d+\.\d+", parsed.hostname or ""):
                url_score -= 0.4
                content_flags.append("ip_based_url")
            # 短链服务
            shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd"}
            if parsed.hostname in shorteners:
                url_score -= 0.2
                content_flags.append("url_shortener")
            # URL 中包含 @ 符号（重定向欺骗）
            if "@" in url:
                url_score -= 0.3
                content_flags.append("url_with_at_sign")
            # 过多的子域名
            if parsed.hostname and parsed.hostname.count(".") > 3:
                url_score -= 0.2
                content_flags.append("excessive_subdomains")

        # --- 内容规则 ---
        combined_text = f"{email.subject} {email.body}".lower()
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                content_flags.append("phishing_keyword_pattern")
                break

        # 限制分数范围
        sender_score = max(0.0, min(1.0, sender_score))
        url_score = max(0.0, min(1.0, url_score))

        return {
            "sender_score": sender_score,
            "url_score": url_score,
            "content_flags": list(set(content_flags)),
        }

    def _is_typo(self, domain: str, trusted: str) -> bool:
        """
        检测域名是否为可信域名的拼写变体（简化的编辑距离检测）
        
        例：g00gle.com vs google.com
        """
        if not domain or not trusted:
            return False
        # 移除 TLD 后比较
        d_base = domain.split(".")[0]
        t_base = trusted.split(".")[0]
        if len(d_base) != len(t_base):
            return False
        # 允许 1-2 个字符差异
        diff = sum(1 for a, b in zip(d_base, t_base) if a != b)
        return 1 <= diff <= 2

    def _extract_urls(self, text: str) -> list[str]:
        """从文本中提取所有 URL"""
        url_pattern = r'https?://[^\s<>"\')\]]+'
        return re.findall(url_pattern, text)

    def _fuse_score(
        self,
        rule_score: float,
        llm_score: float,
        llm_weight: float = 0.7,
    ) -> float:
        """加权融合规则分数和 LLM 分数"""
        return rule_score * (1 - llm_weight) + llm_score * llm_weight

    def _build_prompt(
        self,
        email: EmailInput,
        rule_results: dict,
        semantic_result: SemanticResult | None,
    ) -> str:
        """构造 LLM 分析提示，包含规则扫描结果和语义分析结果"""
        parts = []
        if email.subject:
            parts.append(f"主题: {email.subject}")
        if email.sender:
            parts.append(f"发件人: {email.sender}")
        if email.body:
            parts.append(f"正文:\n{email.body}")
        
        all_urls = email.urls + self._extract_urls(email.body)
        if all_urls:
            parts.append(f"包含的URL: {', '.join(all_urls)}")

        parts.append(f"\n--- 规则扫描预处理结果 ---")
        parts.append(f"发件人规则评分: {rule_results['sender_score']:.2f}")
        parts.append(f"URL规则评分: {rule_results['url_score']:.2f}")
        if rule_results["content_flags"]:
            parts.append(f"规则检测标记: {', '.join(rule_results['content_flags'])}")

        if semantic_result:
            parts.append(f"\n--- 语义分析结果 ---")
            parts.append(f"判定意图: {semantic_result.intent}")
            parts.append(f"话术类型: {', '.join(semantic_result.persuasion_techniques)}")

        return "请对以下邮件进行技术安全分析：\n\n" + "\n".join(parts)
