"""
威胁情报关联 Agent
==================
将邮件特征与已知威胁模式进行关联：
- URL/域名 IOC 模式匹配
- 已知钓鱼话术库匹配
- ATT&CK 技战术初步映射
- 与本地知识库条目交叉验证
"""

import re
import logging

from src.agents.base import BaseAgent, EventCallback
from src.models import EmailInput
from src import database as db
from src.tools import get_tools_for_agent, TRUSTED_DOMAINS

logger = logging.getLogger(__name__)


class ThreatIntelResult:
    """威胁情报关联结果"""

    def __init__(
        self,
        ioc_count: int = 0,
        ioc_list: list = None,
        known_threats: int = 0,
        threat_patterns: list = None,
        attack_techniques: list = None,
        kb_hits: list = None,
        threat_score: float = 0.0,
        explanation: str = "",
    ):
        self.ioc_count = ioc_count
        self.ioc_list = ioc_list or []
        self.known_threats = known_threats
        self.threat_patterns = threat_patterns or []
        self.attack_techniques = attack_techniques or []
        self.kb_hits = kb_hits or []
        self.threat_score = threat_score
        self.explanation = explanation

    def to_dict(self) -> dict:
        return {
            "ioc_count": self.ioc_count,
            "ioc_list": self.ioc_list,
            "known_threats": self.known_threats,
            "threat_patterns": self.threat_patterns,
            "attack_techniques": self.attack_techniques,
            "kb_hits": self.kb_hits,
            "threat_score": self.threat_score,
            "explanation": self.explanation,
        }


class ThreatIntelAgent(BaseAgent):
    """威胁情报关联 Agent"""

    name = "威胁情报关联"
    icon = "🛰️"
    tools = get_tools_for_agent("threat_intel")

    # 已知钓鱼 URL/域名模式
    IOC_PATTERNS = [
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?", "ip_address_url", "使用 IP 地址的链接"),
        (r"https?://[^\s\"]+verify[^\s\"]*", "verify_keyword", "URL 包含 verify/验证关键词"),
        (r"https?://[^\s\"]+login[^\s\"]*", "login_keyword", "URL 包含 login/登录关键词"),
        (r"https?://[^\s\"]+account[^\s\"]*", "account_keyword", "URL 包含 account/账户关键词"),
        (r"https?://[^\s\"]+secure[^\s\"]*", "secure_keyword", "URL 包含 secure/安全关键词"),
        (r"https?://[^\s\"]+update[^\s\"]*", "update_keyword", "URL 包含 update/更新关键词"),
        (r"bit\.ly|t\.co|tinyurl|goo\.gl|short\.link", "url_shortener", "使用短链接服务"),
    ]

    # 已知钓鱼话术模式
    THREAT_PATTERNS = {
        "urgency_pressure": ["紧急", "立即", "马上", "限时", "24小时", "urgent", "immediately", "asap"],
        "account_suspension": ["冻结", "暂停", "封禁", "suspend", "frozen", "blocked", "restricted"],
        "credential_theft": ["密码", "验证码", "验证", "登录", "password", "verification", "confirm identity"],
        "reward_lure": ["中奖", "领奖", "免费", "reward", "winner", "prize", "free gift"],
        "authority_impersonation": ["官方", "客服", "系统", "admin", "security team", "support"],
        "fear_uncertainty": ["异常", "风险", "盗用", "unusual", "suspicious", "unauthorized"],
    }

    # ATT&CK 映射
    ATTACK_TECHNIQUES = {
        "urgency_pressure": "T1566.001 (Spearphishing Attachment/Link - Urgency)",
        "account_suspension": "T1496 (Resource Hijacking via Account Threat)",
        "credential_theft": "T1566.002 (Spearphishing Link) / T1078 (Valid Accounts)",
        "reward_lure": "T1566.001 (Spearphishing Link - Lure)",
        "authority_impersonation": "T1036.005 (Match Legitimate Name or ID)",
        "fear_uncertainty": "T1566.001 (Spearphishing Link - Fear)",
        "ip_address_url": "T1598 (Phishing for Information)",
        "url_shortener": "T1027.002 (Obfuscated Files or Information)",
        "verify_keyword": "T1598 (Phishing for Information)",
        "login_keyword": "T1566.002 (Spearphishing Link)",
    }

    def analyze(self, email: EmailInput, callback: EventCallback = None, **kwargs) -> dict:
        self.emit_sub_step("开始威胁情报关联分析", callback=callback)

        result = ThreatIntelResult()

        # 1. 提取 IOC
        text_to_scan = f"{email.subject or ''}\n{email.body or ''}"

        for pattern, ioc_type, description in self.IOC_PATTERNS:
            matches = re.findall(pattern, text_to_scan, re.IGNORECASE)
            for match in matches:
                result.ioc_list.append({
                    "value": match,
                    "type": ioc_type,
                    "description": description,
                })

        result.ioc_count = len(result.ioc_list)
        self.emit_sub_step(f"发现 {result.ioc_count} 个 IOC 指标", callback=callback)

        # 1.5 主动联网搜索公开情报（Agent 默认触发，确保每次检测都检索公开情报）
        web_search_summary = ""
        web_results = []
        web_threat_score = 0
        web_threat_types = []
        web_evidence = []
        web_findings = []
        query = self._build_search_query(email)
        self.emit_sub_step(f"正在检索网页（{query[:60]}）......", "running", callback)
        try:
            search_result = self.call_tool("web_search", query, 5, callback=callback)
            web_search_summary = search_result.output
            web_results = getattr(search_result, "extra", {}).get("results", [])
            # 提取联网情报威胁指标，实际影响最终威胁评分
            threat_indicators = getattr(search_result, "extra", {}).get("threat_indicators", {})
            web_threat_score = threat_indicators.get("score", 0)
            web_threat_types = threat_indicators.get("matched_types", [])
            web_evidence = threat_indicators.get("evidence", [])
            # 提取深度威胁情报发现
            threat_intel_data = getattr(search_result, "extra", {}).get("threat_intel", {})
            web_findings = threat_intel_data.get("findings", [])
            page_contents = getattr(search_result, "extra", {}).get("page_contents", [])

            # 逐条推送检索到的网页名称，让用户看到 Agent 正在检索哪些公开情报源
            if web_results:
                for r in web_results:
                    title = (r.get("title", "") or "无标题").strip()
                    self.emit_sub_step(f"正在检索网页（{title[:70]}）......", "running", callback)

                # 推送深度抓取的网页正文信息
                if page_contents:
                    for pc in page_contents:
                        title = (pc.get("title", "") or "无标题").strip()
                        preview = (pc.get("content_preview", "") or "")[:120]
                        self.emit_sub_step(
                            f"已抓取网页正文（{title[:50]}）：{preview}......",
                            "running", callback,
                        )

                # 推送威胁情报发现
                if web_findings:
                    for finding in web_findings[:3]:
                        self.emit_sub_step(f"威胁情报发现：{finding[:120]}", "running", callback)

                if web_threat_score > 0:
                    evidence_str = ""
                    if web_evidence:
                        evidence_str = f"（证据：{'; '.join(web_evidence[:3])}）"
                    self.emit_sub_step(
                        f"联网情报分析：命中 {len(web_threat_types)} 类威胁信号（{', '.join(web_threat_types)}），"
                        f"深度抓取 {len(page_contents)} 个网页，联网情报风险分 +{web_threat_score}{evidence_str}",
                        "done", callback,
                    )
                else:
                    self.emit_sub_step(
                        f"联网情报检索完成，共检索 {len(web_results)} 个公开网页，深度抓取 {len(page_contents)} 个网页正文，未发现明显威胁信号",
                        "done", callback,
                    )
            else:
                self.emit_sub_step(
                    "联网检索未获取到公开结果，已退回本地规则与知识库分析",
                    "done", callback,
                )
        except Exception as e:
            self.emit_sub_step(f"联网搜索未成功：{str(e)[:100]}，继续本地分析", "done", callback)
            web_search_summary = f"联网搜索失败：{str(e)[:100]}"

        # 2. 话术模式匹配
        matched_patterns = set()
        text_lower = text_to_scan.lower()
        for pattern_name, keywords in self.THREAT_PATTERNS.items():
            for kw in keywords:
                if kw in text_lower:
                    matched_patterns.add(pattern_name)
                    break

        result.threat_patterns = list(matched_patterns)
        result.known_threats = len(matched_patterns)
        if matched_patterns:
            self.emit_sub_step(
                f"匹配到 {len(matched_patterns)} 种已知威胁话术：{', '.join(matched_patterns)}",
                callback=callback,
            )

        # 3. ATT&CK 映射
        attack_techniques = []
        for pattern in matched_patterns:
            if pattern in self.ATTACK_TECHNIQUES:
                attack_techniques.append(self.ATTACK_TECHNIQUES[pattern])

        # IOC 类型也映射 ATT&CK
        for ioc in result.ioc_list:
            ioc_type = ioc["type"]
            if ioc_type in self.ATTACK_TECHNIQUES:
                attack_techniques.append(self.ATTACK_TECHNIQUES[ioc_type])

        result.attack_techniques = attack_techniques
        if attack_techniques:
            self.emit_sub_step(
                f"映射到 {len(attack_techniques)} 个 ATT&CK 技战术",
                callback=callback,
            )

        # 4. 知识库交叉验证
        try:
            kb_results = db.search_kb(text_to_scan[:200], limit=5)
            result.kb_hits = kb_results if isinstance(kb_results, list) else []
        except Exception:
            result.kb_hits = []

        if result.kb_hits:
            self.emit_sub_step(
                f"知识库命中 {len(result.kb_hits)} 条相关条目",
                callback=callback,
            )

        # 5. 计算威胁评分（含联网情报贡献）
        result.threat_score = self._calc_threat_score(result, web_threat_score)
        self.emit_sub_step(
            f"威胁评分：{result.threat_score:.0f}/100（含联网情报 +{web_threat_score}）",
            callback=callback,
        )

        # 6. 生成说明
        result.explanation = self._build_explanation(result, web_search_summary, web_threat_types)
        self.emit_sub_step("威胁情报关联分析完成", callback=callback)

        return {"threat_intel": result}

    def _calc_threat_score(self, result: ThreatIntelResult, web_threat_score: float = 0) -> float:
        score = 0.0

        # IOC 指标加分
        score += min(result.ioc_count * 15, 45)

        # 话术模式加分
        high_risk_patterns = {"credential_theft", "urgency_pressure", "authority_impersonation"}
        for pattern in result.threat_patterns:
            if pattern in high_risk_patterns:
                score += 20
            else:
                score += 10

        # 知识库命中加分
        score += min(len(result.kb_hits) * 8, 20)

        # 联网情报威胁信号加分（实际影响评分）
        score += web_threat_score

        return min(score, 100)

    def _should_web_search(self, email: EmailInput) -> bool:
        """
        Agent 自行判断是否需要联网检索公开情报。
        触发条件：
        1. 用户显式要求；
        2. 发现 IOC 指标（IP/短链/可疑 URL 等）；
        3. 命中高威胁话术（凭证窃取/紧急施压/权威冒充/账户冻结）；
        4. 发件人域名看起来可疑且非高可信域名。
        """
        text_to_scan = f"{email.subject or ''}\n{email.body or ''}"

        # 1. 用户显式要求
        if email.prompt:
            prompt_lower = email.prompt.lower()
            trigger_words = ["搜索", "search", "联网", "web", "查", "查查", "检索", "公开情报"]
            if any(word in prompt_lower for word in trigger_words):
                return True

        # 2. 发现 IOC 指标
        ioc_count = sum(
            len(re.findall(pattern, text_to_scan, re.IGNORECASE))
            for pattern, _, _ in self.IOC_PATTERNS
        )
        if ioc_count > 0:
            return True

        # 3. 命中高威胁话术
        high_risk_patterns = {"credential_theft", "urgency_pressure", "authority_impersonation", "account_suspension"}
        text_lower = text_to_scan.lower()
        matched_patterns = set()
        for pattern_name, keywords in self.THREAT_PATTERNS.items():
            if any(kw in text_lower for kw in keywords):
                matched_patterns.add(pattern_name)
        if matched_patterns & high_risk_patterns:
            return True

        # 4. 发件人域名可疑
        if email.sender and "@" in email.sender:
            domain = email.sender.split("@")[-1].lower().strip().rstrip(">")
            if not any(domain.endswith(d) for d in TRUSTED_DOMAINS):
                suspicious_keywords = ["verify", "secure", "account", "login", "bank", "update", "confirm", "service", "support", "official"]
                if any(kw in domain for kw in suspicious_keywords):
                    return True

        return False

    def _build_search_query(self, email: EmailInput) -> str:
        """构造联网搜索查询词，优先指向公开威胁报告/情报源。"""
        candidates = []
        # 优先使用发件人域名和邮件中的 URL（英文关键词更易命中权威情报源）
        if email.sender and "@" in email.sender:
            domain = email.sender.split("@")[-1].strip().rstrip(">")
            candidates.append(f"{domain} phishing scam")
        url_match = re.search(r'https?://([^/\s]+)', email.body or "")
        if url_match:
            host = url_match.group(1)
            candidates.append(f"{host} phishing scam report")
        if not candidates:
            # 兜底：用主题的英文部分
            subject = email.subject or ""
            if subject:
                candidates.append(f"{subject[:40]} phishing scam")
            else:
                candidates.append("phishing email scam report")
        # 只取第一个候选，避免查询过长导致 DuckDuckGo 拒绝
        return candidates[0]

    def _build_explanation(self, result: ThreatIntelResult, web_search_summary: str = "", web_threat_types: list = None) -> str:
        """生成威胁情报分析说明"""
        parts = []

        if result.ioc_list:
            ioc_descs = [ioc["description"] for ioc in result.ioc_list[:5]]
            parts.append(f"IOC 指标（{result.ioc_count} 个）：{', '.join(ioc_descs)}。")

        if result.threat_patterns:
            parts.append(f"匹配威胁话术：{', '.join(result.threat_patterns)}。")

        if result.attack_techniques:
            parts.append(f"ATT&CK 映射：{', '.join(result.attack_techniques[:3])}。")

        if result.kb_hits:
            parts.append(f"知识库命中 {len(result.kb_hits)} 条。")

        if web_search_summary and "失败" not in web_search_summary and "未获取" not in web_search_summary:
            snippet = web_search_summary[:280].replace("\n", " ")
            parts.append(f"公开情报检索：{snippet}...")
            if web_threat_types:
                parts.append(f"联网情报命中威胁类型：{', '.join(web_threat_types)}。")
        elif web_search_summary and "失败" in web_search_summary:
            parts.append("公开情报检索未成功，已退回本地规则分析。")

        parts.append(f"威胁评分 {result.threat_score:.0f}/100。")

        return " ".join(parts) if parts else "未发现明显威胁情报关联。"
