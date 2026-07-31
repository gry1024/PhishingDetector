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

        # 5. 计算威胁评分
        result.threat_score = self._calc_threat_score(result)
        self.emit_sub_step(
            f"威胁评分：{result.threat_score:.0f}/100",
            callback=callback,
        )

        # 6. 生成说明
        result.explanation = self._build_explanation(result)
        self.emit_sub_step("威胁情报关联分析完成", callback=callback)

        return {"threat_intel": result}

    def _calc_threat_score(self, result: ThreatIntelResult) -> float:
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

        return min(score, 100)

    def _build_explanation(self, result: ThreatIntelResult) -> str:
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

        parts.append(f"威胁评分 {result.threat_score:.0f}/100。")

        return " ".join(parts) if parts else "未发现明显威胁情报关联。"
