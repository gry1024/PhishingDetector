"""
多维关联检测 Agent（Agent #2）
==============================
核心职责：从技术维度检测邮件的安全特征。

工具集：
- analyze_url: 分析 URL 安全特征（IP域名、短链、可疑TLD等）
- check_sender_domain: 检测发件人域名可信度
- scan_phishing_patterns: 正则扫描钓鱼话术
- extract_urls: 提取邮件中的 URL

工作流：
1. 调用工具对每个 URL 做安全分析
2. 调用工具检测发件人域名
3. 调用工具扫描关键词模式
4. 将工具结果 + 邮件全文传给 LLM 做深度技术分析
5. 融合工具分数和 LLM 分析结果
"""

from src.agents.base import BaseAgent, EventCallback
from src.models import EmailInput, DetectionResult, SemanticResult
from src.tools import DETECTOR_TOOLS, extract_urls


SYSTEM_PROMPT = """你是一个邮件安全技术检测专家。基于工具预扫描结果，进行深度技术分析。

分析维度：
1. 发件人可信度(0-1): 域名仿冒、免费邮箱、格式异常
2. URL安全性(0-1): 可疑域名、短链、IP地址、异常端口
3. 内容标记: suspicious_link, brand_impersonation, credential_request, urgency_language 等

以严格JSON返回：
{
    "sender_score": 0.0到1.0,
    "sender_analysis": "发件人分析",
    "url_score": 0.0到1.0,
    "url_analysis": "URL分析",
    "content_flags": ["标记列表"],
    "explanation": "综合分析说明"
}"""


class DetectorAgent(BaseAgent):
    """多维关联检测 Agent"""

    name = "多维关联检测"
    icon = "🔍"
    tools = DETECTOR_TOOLS

    def analyze(
        self,
        email: EmailInput,
        callback: EventCallback = None,
        semantic_result: SemanticResult = None,
        **kwargs,
    ) -> dict:
        """
        执行多维检测

        流程：URL分析 → 发件人检测 → 关键词扫描 → LLM深度分析 → 分数融合
        """
        # ---- Step 1: 提取并分析所有 URL ----
        combined_text = f"{email.subject} {email.body}"
        url_extract = self.call_tool("extract_urls", combined_text, callback=callback)

        all_urls = email.urls.copy()
        # 从提取结果中解析 URL
        if url_extract.output.startswith("提取到"):
            import re
            extracted = re.findall(r'https?://\S+', url_extract.output)
            all_urls.extend(extracted)
        all_urls = list(set(all_urls))

        # 逐个分析 URL
        url_tool_results = []
        for url in all_urls[:5]:  # 最多分析 5 个
            r = self.call_tool("analyze_url", url, callback=callback)
            url_tool_results.append(r)

        # ---- Step 2: 发件人域名检测 ----
        sender_result = self.call_tool("check_sender_domain", email.sender, callback=callback)

        # ---- Step 3: 关键词扫描 ----
        pattern_result = self.call_tool("scan_phishing_patterns", combined_text, callback=callback)

        # ---- Step 4: LLM 深度分析 ----
        user_prompt = self._build_prompt(email, all_urls, semantic_result)
        try:
            llm_result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)
        except Exception:
            self.emit_thinking("LLM不可用，启用规则化技术兜底分析...", callback)
            llm_result = self._fallback_detection_result(
                email=email,
                sender_result=sender_result,
                url_tool_results=url_tool_results,
                pattern_result=pattern_result,
                semantic_result=semantic_result,
            )

        # ---- Step 5: 分数融合（工具 + LLM） ----
        # 发件人分数：从工具结果解析
        sender_trust = self._parse_score(sender_result.output, "可信度")
        llm_sender = float(llm_result.get("sender_score", 0.5))
        sender_score = sender_trust / 100 * 0.4 + llm_sender * 0.6

        # URL 分数：取所有 URL 中最低的风险分的反转
        url_risk = max(
            (self._parse_score(r.output, "风险分") for r in url_tool_results),
            default=0,
        )
        llm_url = float(llm_result.get("url_score", 0.5))
        url_score = (1 - url_risk / 100) * 0.4 + llm_url * 0.6

        header_risk = self._header_risk_score(email.headers)
        sender_score = max(0, min(1, (sender_score * 0.8) + (1 - header_risk / 100) * 0.2))
        url_score = max(0, min(1, (url_score * 0.85) + (1 - url_risk / 100) * 0.15))

        content_flags = list(set(llm_result.get("content_flags", [])))
        content_flags.extend(self._build_content_flags(email, all_urls, url_risk, header_risk))
        content_flags = list(dict.fromkeys(content_flags))

        detection = DetectionResult(
            sender_score=max(0, min(1, sender_score)),
            sender_analysis=llm_result.get("sender_analysis", sender_result.output),
            url_score=max(0, min(1, url_score)),
            url_analysis=llm_result.get("url_analysis", ""),
            content_flags=content_flags,
            explanation=llm_result.get("explanation", ""),
        )

        return {"detection": detection}

    def _fallback_detection_result(self, email, sender_result, url_tool_results, pattern_result, semantic_result) -> dict:
        """LLM 不可用时的规则化技术兜底结果。"""
        sender_trust = self._parse_score(sender_result.output, "可信度")
        url_risk = max(
            (self._parse_score(r.output, "风险分") for r in url_tool_results),
            default=0,
        )
        header_risk = self._header_risk_score(email.headers)
        content_flags = self._build_content_flags(email, email.urls, url_risk, header_risk)

        if "免费邮箱" in sender_result.output or header_risk >= 40:
            sender_analysis = "发件人可信度下降：存在免费邮箱或邮件头校验异常。"
        else:
            sender_analysis = "发件人域名未发现明显仿冒，但仍建议进一步校验。"

        url_analysis = (
            f"URL 校验结果显示风险分 {url_risk}/100，"
            f"规则配置已将该邮件标记为需要进一步人工复核。"
        )

        return {
            "sender_score": max(0, min(1, sender_trust / 100)),
            "sender_analysis": sender_analysis,
            "url_score": max(0, min(1, 1 - url_risk / 100)),
            "url_analysis": url_analysis,
            "content_flags": content_flags,
            "explanation": "LLM不可用时使用规则引擎进行安全兜底判定，重点关注发件人可信度、URL异常、邮件头校验和附件风险。",
        }

    def _header_risk_score(self, headers: dict) -> float:
        """解析 SPF / DKIM / DMARC 头部校验状态。"""
        headers = headers or {}
        score = 0.0
        spf = str(headers.get("spf", "")).lower()
        dkim = str(headers.get("dkim", "")).lower()
        dmarc = str(headers.get("dmarc", "")).lower()

        if spf in {"none", "neutral"}:
            score += 20
        if spf == "fail":
            score += 40
        if dkim in {"none", "neutral"}:
            score += 20
        if dkim == "fail":
            score += 40
        if dmarc in {"none", "neutral"}:
            score += 20
        if dmarc == "fail":
            score += 40
        return min(score, 100)

    def _build_content_flags(self, email, urls, url_risk, header_risk) -> list[str]:
        """构建增强的内容标记列表。"""
        flags = []
        if url_risk >= 60:
            flags.append("suspicious_link")
        if email.has_attachment:
            flags.append("possible_attachment_scam")
        if header_risk >= 40:
            flags.append("email_header_validation_failed")
        if any("verify" in u.lower() or "secure" in u.lower() for u in urls):
            flags.append("credential_request")
        return flags

    def _parse_score(self, text: str, prefix: str) -> float:
        """从工具输出文本中解析分数（如 '风险分: 45/100' → 45.0）"""
        import re
        match = re.search(rf'{prefix}:\s*(\d+)', text)
        return float(match.group(1)) if match else 50.0

    def _build_prompt(
        self,
        email: EmailInput,
        urls: list[str],
        semantic: SemanticResult = None,
    ) -> str:
        """构造 LLM 提示"""
        parts = []
        if email.subject:
            parts.append(f"主题: {email.subject}")
        if email.sender:
            parts.append(f"发件人: {email.sender}")
        if email.body:
            parts.append(f"正文:\n{email.body}")
        if urls:
            parts.append(f"URL列表: {', '.join(urls)}")

        if semantic:
            parts.append(f"\n[语义分析结果] 意图:{semantic.intent} 话术:{','.join(semantic.persuasion_techniques)}")

        return "请对以下邮件进行技术安全分析：\n\n" + "\n".join(parts)
