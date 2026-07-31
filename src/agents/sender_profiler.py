"""
发件人画像分析 Agent
==================
构建发件人的多维画像：
- 域名类型识别（免费邮箱、企业邮箱、可疑 TLD）
- 品牌仿冒 / 相似域名检测
- 域名声誉评分（规则-based）
- 发件人地址结构异常（随机字符、子域名滥用等）
"""

import re
import logging

from src.agents.base import BaseAgent, EventCallback
from src.models import EmailInput

logger = logging.getLogger(__name__)


class SenderProfilerResult:
    """发件人画像结果"""

    def __init__(
        self,
        sender_type: str = "unknown",
        domain_age_indicator: str = "unknown",
        domain_reputation: str = "unknown",
        reputation_score: float = 0.5,
        lookalike_domains: list[str] = None,
        brand_impersonated: str = "",
        address_entropy: float = 0.0,
        subdomain_depth: int = 0,
        suspicious_patterns: list[str] = None,
        explanation: str = "",
    ):
        self.sender_type = sender_type
        self.domain_age_indicator = domain_age_indicator
        self.domain_reputation = domain_reputation
        self.reputation_score = reputation_score
        self.lookalike_domains = lookalike_domains or []
        self.brand_impersonated = brand_impersonated
        self.address_entropy = address_entropy
        self.subdomain_depth = subdomain_depth
        self.suspicious_patterns = suspicious_patterns or []
        self.explanation = explanation

    def to_dict(self) -> dict:
        return {
            "sender_type": self.sender_type,
            "domain_age_indicator": self.domain_age_indicator,
            "domain_reputation": self.domain_reputation,
            "reputation_score": self.reputation_score,
            "lookalike_domains": self.lookalike_domains,
            "brand_impersonated": self.brand_impersonated,
            "address_entropy": self.address_entropy,
            "subdomain_depth": self.subdomain_depth,
            "suspicious_patterns": self.suspicious_patterns,
            "explanation": self.explanation,
        }


class SenderProfilerAgent(BaseAgent):
    """发件人画像分析 Agent"""

    name = "发件人画像分析"
    icon = "👤"

    # 常见免费邮箱域名
    FREE_EMAIL_DOMAINS = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "qq.com",
        "163.com", "126.com", "sina.com", "sohu.com", "foxmail.com",
        "icloud.com", "me.com", "live.com", "msn.com", "aol.com",
    }

    # 可疑顶级域
    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".club", ".online", ".site"}

    # 常见被仿冒品牌
    BRAND_DOMAINS = {
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
        "google": ["google.com", "gmail.com", "youtube.com"],
        "amazon": ["amazon.com", "amazon.cn", "amazon.co.uk"],
        "paypal": ["paypal.com"],
        "alipay": ["alipay.com"],
        "wechat": ["wechat.com", "qq.com"],
        "taobao": ["taobao.com", "tmall.com"],
        "bank": ["bankofchina.com", "icbc.com.cn", "ccb.com", "abchina.com"],
    }

    def analyze(self, email: EmailInput, callback: EventCallback = None, **kwargs) -> dict:
        self.emit_sub_step("开始构建发件人画像", callback=callback)

        sender = (email.sender or "").strip()
        result = SenderProfilerResult()

        if not sender or "@" not in sender:
            result.explanation = "发件人地址缺失或格式异常，无法构建画像。"
            self.emit_sub_step(result.explanation, callback=callback)
            return {"sender_profiler": result}

        local, domain = sender.rsplit("@", 1)
        local = local.lower()
        domain = domain.lower()

        # 1. 发件人类型
        if domain in self.FREE_EMAIL_DOMAINS:
            result.sender_type = "free_email"
        elif domain.endswith((".edu", ".gov", ".org", ".cn")) or domain.count(".") >= 2:
            result.sender_type = "corporate"
        elif any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
            result.sender_type = "suspicious_tld"
        else:
            result.sender_type = "generic"

        self.emit_sub_step(f"发件人类型识别为：{result.sender_type}", callback=callback)

        # 2. 子域名深度
        result.subdomain_depth = domain.count(".")
        if result.subdomain_depth >= 3:
            result.suspicious_patterns.append("过深子域名结构")

        # 3. 地址熵（随机字符检测）
        result.address_entropy = self._calculate_entropy(local)
        if result.address_entropy > 4.0 and len(local) > 10:
            result.suspicious_patterns.append("发件人本地部分高度随机")

        # 4. 品牌仿冒检测
        impersonated_brand, lookalikes = self._detect_brand_impersonation(domain)
        result.brand_impersonated = impersonated_brand
        result.lookalike_domains = lookalikes
        if impersonated_brand:
            result.suspicious_patterns.append(f"疑似仿冒品牌：{impersonated_brand}")

        # 5. 域名声誉评分
        result.reputation_score, result.domain_reputation = self._score_reputation(domain, result)

        # 6. 域名年龄指示（无真实 WHOIS 数据，基于规则推断）
        if any(tld in domain for tld in self.SUSPICIOUS_TLDS):
            result.domain_age_indicator = "likely_new"
        elif domain in self.FREE_EMAIL_DOMAINS:
            result.domain_age_indicator = "established"
        else:
            result.domain_age_indicator = "unknown"

        # 7. 生成说明
        result.explanation = self._build_explanation(sender, domain, result)

        self.emit_sub_step(
            f"发件人画像完成：类型={result.sender_type}, 声誉={result.domain_reputation}, "
            f"评分={result.reputation_score:.2f}, 发现 {len(result.suspicious_patterns)} 个可疑模式",
            callback=callback,
        )

        return {"sender_profiler": result}

    def _calculate_entropy(self, text: str) -> float:
        """计算字符串的香农熵"""
        if not text:
            return 0.0
        import math
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _detect_brand_impersonation(self, domain: str) -> tuple[str, list[str]]:
        """检测是否仿冒知名品牌域名"""
        lookalikes = []
        impersonated = ""

        # 提取核心域名（去掉 TLD）
        core = domain.rsplit(".", 1)[0] if "." in domain else domain

        for brand, official_domains in self.BRAND_DOMAINS.items():
            # 直接包含品牌名但不是官方域名
            if brand in core:
                if not any(d in domain for d in official_domains):
                    impersonated = brand
                    lookalikes.append(domain)
                    break

            # 相似字符替换检测（简化版）
            lookalike_variants = self._generate_lookalikes(brand)
            if any(v in core for v in lookalike_variants):
                if not any(d in domain for d in official_domains):
                    impersonated = brand
                    lookalikes.append(domain)
                    break

        return impersonated, lookalikes

    def _generate_lookalikes(self, brand: str) -> list[str]:
        """生成简单的相似域名变体"""
        variants = []
        replacements = {
            "a": ["4", "@"],
            "e": ["3"],
            "i": ["1", "l"],
            "o": ["0"],
            "s": ["5", "$"],
            "t": ["7"],
            "l": ["1", "i"],
        }
        for i, ch in enumerate(brand):
            for repl in replacements.get(ch, []):
                variants.append(brand[:i] + repl + brand[i + 1:])
        return variants

    def _score_reputation(self, domain: str, result: SenderProfilerResult) -> tuple[float, str]:
        """返回声誉评分（0-1，越高越可信）和评级"""
        score = 0.5

        if domain in self.FREE_EMAIL_DOMAINS:
            score = 0.6
        elif result.sender_type == "corporate":
            score = 0.75

        if result.sender_type == "suspicious_tld":
            score -= 0.35
        if result.brand_impersonated:
            score -= 0.45
        if result.suspicious_patterns:
            score -= min(len(result.suspicious_patterns) * 0.12, 0.35)
        if result.subdomain_depth >= 3:
            score -= 0.15
        if result.address_entropy > 4.0:
            score -= 0.15

        score = max(0.0, min(1.0, score))

        if score >= 0.75:
            reputation = "trusted"
        elif score >= 0.55:
            reputation = "neutral"
        elif score >= 0.35:
            reputation = "suspicious"
        else:
            reputation = "malicious"

        return score, reputation

    def _build_explanation(self, sender: str, domain: str, result: SenderProfilerResult) -> str:
        parts = [f"发件人 {sender} 类型为「{result.sender_type}」，域名声誉评级「{result.domain_reputation}」。"]
        if result.brand_impersonated:
            parts.append(f"检测到疑似仿冒品牌「{result.brand_impersonated}」于域名 {domain}。")
        if result.lookalike_domains:
            parts.append(f"相似域名/变体：{', '.join(result.lookalike_domains)}。")
        if result.suspicious_patterns:
            parts.append(f"可疑模式：{'; '.join(result.suspicious_patterns)}。")
        parts.append(f"声誉评分 {result.reputation_score:.2f}/1.0，子域名深度 {result.subdomain_depth}。")
        return " ".join(parts)
