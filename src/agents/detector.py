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
6. LLM 不可用时自动启用规则化技术兜底
"""

from src.agents.base import BaseAgent, EventCallback
from src.models import EmailInput, DetectionResult, SemanticResult
from src.tools import get_tools_for_agent, extract_urls
from src import database as db


SYSTEM_PROMPT = """你是一个邮件安全技术检测专家。基于工具预扫描结果，进行深度技术分析。

分析维度：
1. 发件人可信度(0-1): 域名仿冒、免费邮箱、格式异常
2. URL安全性(0-1): 可疑域名、短链、IP地址、异常端口
3. 内容标记: suspicious_link, brand_impersonation, credential_request, urgency_language 等

请先用自然语言详细分析发件人身份、URL安全和内容特征（200-400字），
然后在新的一行输出 <<<JSON>>> 标记，最后输出严格 JSON：
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
    tools = get_tools_for_agent("detector")

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
        LLM 不可用时自动降级为规则化技术兜底。
        """
        # ---- Step 1: 提取并分析所有 URL ----
        combined_text = f"{email.subject} {email.body}"

        self.emit_thinking("第一步：提取邮件中的 URL，并对每个 URL 进行多维安全分析。", callback)
        self.emit_sub_step("从邮件主题和正文中提取所有 URL 候选", "running", callback)
        url_extract = self.call_tool("extract_urls", combined_text, callback=callback)
        self.emit_sub_step(f"URL 提取结果：{url_extract.output}", "done", callback)

        all_urls = email.urls.copy()
        # 从提取结果中解析 URL
        if url_extract.output.startswith("提取到"):
            import re
            extracted = re.findall(r'https?://\S+', url_extract.output)
            all_urls.extend(extracted)
        all_urls = list(set(all_urls))

        # 逐个分析 URL
        url_tool_results = []
        url_reputation_results = []
        if all_urls:
            self.emit_sub_step(f"发现 {len(all_urls[:5])} 个 URL，逐一分析域名结构、IP 形式、端口、路径异常", "running", callback)
            for idx, url in enumerate(all_urls[:5], 1):  # 最多分析 5 个
                self.emit_sub_step(f"正在分析第 {idx}/{len(all_urls[:5])} 个 URL: {url[:60]}...", "running", callback)
                r = self.call_tool("analyze_url", url, callback=callback)
                url_tool_results.append(r)
                reputation = self.call_tool("check_url_reputation", url, callback=callback)
                url_reputation_results.append(reputation)
            self.emit_sub_step(f"URL 安全分析与信誉检查完成，综合风险分 {max((self._parse_score(r.output, '风险分') for r in url_tool_results), default=0):.0f}/100", "done", callback)
        else:
            self.emit_sub_step("邮件中未检测到 URL，跳过 URL 安全分析", "done", callback)

        # ---- Step 2: 附件与行为异常分析 ----
        self.emit_thinking("第二步：分析附件风险与行为异常模式，识别 BEC 和商业欺诈特征。", callback)
        if email.has_attachment:
            self.emit_sub_step("邮件包含附件，调用附件风险分析器检测诱导文件名和异常类型", "running", callback)
            attachment_result = self.call_tool("analyze_attachment_risk", combined_text, callback=callback)
            self.emit_sub_step(f"附件风险分析完成：{attachment_result.output}", "done", callback)
        else:
            self.emit_sub_step("邮件无附件，跳过附件风险分析", "done", callback)
            attachment_result = None

        self.emit_sub_step("分析发件人行为、主题语气、正文行为诱导等异常模式", "running", callback)
        behavior_result = self.call_tool(
            "analyze_behavior_anomalies",
            f"{email.sender}\n{email.subject}\n{email.body}",
            callback=callback,
        )
        self.emit_sub_step(f"行为异常分析完成：{behavior_result.output}", "done", callback)

        # ---- Step 2.5: 知识库检索（RAG-MVP） ----
        self.emit_thinking("第三步：检索本地知识库，匹配已知钓鱼攻击模式。", callback)
        kb_query_text = "\n".join([
            email.subject or "",
            email.sender or "",
            email.body or "",
            " ".join(all_urls),
        ])
        self.emit_sub_step("将邮件主题、发件人、正文、URL 拼接为知识库查询向量", "running", callback)
        kb_hits = db.search_kb(kb_query_text, limit=5)
        if kb_hits:
            top_titles = "；".join(hit["title"] for hit in kb_hits[:3])
            self.emit_sub_step(f"命中知识库 {len(kb_hits)} 条：{top_titles}", "done", callback)
        else:
            self.emit_sub_step("未命中知识库条目，继续按规则与 LLM 分析", "done", callback)

        # ---- Step 3: 发件人域名检测 ----
        self.emit_thinking("第四步：校验发件人域名可信度，识别品牌仿冒和免费邮箱。", callback)
        self.emit_sub_step("解析发件人域名，检查是否为知名品牌仿冒、异常子域名或免费邮箱", "running", callback)
        sender_result = self.call_tool("check_sender_domain", email.sender, callback=callback)
        self.emit_sub_step(f"发件人检测完成：{sender_result.output}", "done", callback)

        # ---- Step 4: 关键词扫描 ----
        self.emit_thinking("第五步：扫描邮件内容中的风险关键词，形成内容标记。", callback)
        self.emit_sub_step("扫描中文与英文钓鱼关键词库，生成内容标记列表", "running", callback)
        pattern_result = self.call_tool("scan_phishing_patterns", combined_text, callback=callback)
        self.emit_sub_step(f"关键词扫描完成：{pattern_result.output}", "done", callback)

        # ---- Step 5: LLM 深度分析（带规则兜底） ----
        self.emit_thinking(
            "第六步：将工具扫描结果汇总，调用 LLM 进行多维关联检测与综合研判。\n"
            "   检测维度：发件人身份 | URL 安全 | 内容特征 | 邮件头校验",
            callback,
        )
        self.emit_sub_step("整合 URL 风险、发件人可信度、行为异常、知识库命中、内容标记为统一提示词", "running", callback)
        user_prompt = self._build_prompt(email, all_urls, semantic_result)
        try:
            llm_result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)
            self.emit_sub_step("LLM 多维关联分析完成，提取结构化检测结果", "done", callback)
        except Exception as e:
            self.emit_thinking("⚠️ LLM 不可用，已启用规则化技术兜底分析。", callback)
            self.emit_sub_step(f"规则兜底接管：基于工具分数融合生成技术判定（原因：{str(e)[:80]}）", "done", callback)
            llm_result = self._fallback_detection_result(
                email=email,
                sender_result=sender_result,
                url_tool_results=url_tool_results,
                pattern_result=pattern_result,
                semantic_result=semantic_result,
            )

        # ---- Step 6: 分数融合（工具 + LLM + 邮件头校验） ----
        self.emit_thinking("第七步：融合多维度分数，生成最终技术检测指标。", callback)
        self.emit_sub_step("解析工具返回的发件人可信度、URL 风险分、信誉分、附件风险分、行为异常分", "running", callback)

        # 发件人分数：从工具结果解析
        sender_trust = self._parse_score(sender_result.output, "可信度")
        llm_sender = float(llm_result.get("sender_score", 0.5))
        sender_score = sender_trust / 100 * 0.4 + llm_sender * 0.6

        # URL 分数：取所有 URL 中最低的风险分的反转
        url_risk = max(
            (self._parse_score(r.output, "风险分") for r in url_tool_results),
            default=0,
        )
        reputation_score = max(
            (self._parse_score(r.output, "信誉分") for r in url_reputation_results),
            default=0,
        )
        attachment_risk = self._parse_score(attachment_result.output, "附件风险分") if attachment_result else 0
        behavior_risk = self._parse_score(behavior_result.output, "行为异常分") if behavior_result else 0
        llm_url = float(llm_result.get("url_score", 0.5))
        url_score = (1 - url_risk / 100) * 0.4 + llm_url * 0.6

        # 邮件头安全校验（SPF/DKIM/DMARC）
        header_risk = self._header_risk_score(email.headers)
        sender_score = max(0, min(1, (sender_score * 0.8) + (1 - header_risk / 100) * 0.2))
        url_score = max(0, min(1, (url_score * 0.85) + (1 - url_risk / 100) * 0.15))

        self.emit_sub_step(
            f"分数融合完成：发件人可信度 {sender_score:.2f}，URL 安全分 {url_score:.2f}，"
            f"邮件头风险 {header_risk:.0f}/100，附件风险 {attachment_risk:.0f}/100，行为异常 {behavior_risk:.0f}/100",
            "done",
            callback,
        )

        # 增强内容标记
        content_flags = list(set(llm_result.get("content_flags", [])))
        content_flags.extend(self._build_content_flags(email, all_urls, url_risk, header_risk))
        if reputation_score <= 50:
            content_flags.append("url_reputation_suspicious")
        if attachment_risk >= 40:
            content_flags.append("suspicious_attachment_name")
        if behavior_risk >= 40:
            content_flags.append("identity_behavior_anomaly")
        if any(hit.get("severity") in {"high", "critical"} for hit in kb_hits):
            content_flags.append("kb_high_risk_hit")
        content_flags = list(dict.fromkeys(content_flags))

        self.emit_sub_step(f"生成内容标记：{', '.join(content_flags) or '无'}", "done", callback)

        kb_summary = ""
        if kb_hits:
            kb_summary = " | ".join(
                f"{hit['title']}({hit['severity']},score={hit['score']})"
                for hit in kb_hits[:3]
            )

        detection = DetectionResult(
            sender_score=max(0, min(1, sender_score)),
            sender_analysis=llm_result.get("sender_analysis", sender_result.output),
            url_score=max(0, min(1, url_score)),
            url_analysis=llm_result.get("url_analysis", ""),
            url_reputation_score=max(0, min(1, reputation_score / 100)),
            url_reputation_summary=next((r.output for r in url_reputation_results if r.output), ""),
            attachment_score=max(0, min(1, attachment_risk / 100)),
            attachment_summary=attachment_result.output if attachment_result else "",
            behavior_score=max(0, min(1, behavior_risk / 100)),
            behavior_summary=behavior_result.output if behavior_result else "",
            content_flags=content_flags,
            kb_hits=kb_hits,
            kb_summary=kb_summary,
            explanation=llm_result.get("explanation", ""),
        )

        self.emit_sub_step(
            f"多维关联检测完成：发现 {len(content_flags)} 个内容标记，命中 {len(kb_hits)} 条知识库规则",
            "done",
            callback,
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
            sender_analysis = (
                "发件人可信度下降：工具检测到免费邮箱或邮件头校验（SPF/DKIM/DMARC）存在异常，"
                "说明邮件身份真实性不足。"
            )
        else:
            sender_analysis = "发件人域名未发现明显仿冒，但建议结合语义意图进一步校验。"

        url_analysis = (
            f"URL 校验结果显示风险分 {url_risk:.0f}/100，"
            f"规则引擎已识别出可疑链接特征，建议将该邮件标记为需要人工复核。"
        )

        return {
            "sender_score": max(0, min(1, sender_trust / 100)),
            "sender_analysis": sender_analysis,
            "url_score": max(0, min(1, 1 - url_risk / 100)),
            "url_analysis": url_analysis,
            "content_flags": content_flags,
            "explanation": (
                "LLM 不可用时使用规则引擎进行安全兜底判定。重点关注："
                "发件人可信度、URL 异常结构、邮件头校验状态、附件风险以及行为异常。"
            ),
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
